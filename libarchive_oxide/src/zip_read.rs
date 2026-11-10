// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded forward-only ZIP reader.

use libarchive_oxide_core::{
    ArchiveDecoder, ArchiveError, ArchiveMetadata, ArchivePath, Chunk, CodecStatus, DecodeEvent,
    DecodeStep, EndOfInput, EntryKind, EntryMetadata, EntryTimes, ErrorKind, Extension, Limits,
    Owner, PathEncoding, Timestamp,
};

#[cfg(any(feature = "xz", feature = "ppmd"))]
use libarchive_oxide_core::Codec;

use crate::filter::gzip::{Crc32, RawInflateDecoder};

#[cfg(feature = "aes")]
use crate::SecretBytes;
#[cfg(feature = "aes")]
use crate::zipaes::ZipAesDecoder;
#[cfg(feature = "aes")]
use crate::zipcrypto::ZipCrypto;

#[cfg(any(feature = "xz", feature = "ppmd"))]
use crate::filter::lzip::LzipDecoder;
#[cfg(feature = "xz")]
use crate::filter::xz::XzStreamBoundary;

#[cfg(any(feature = "zstd", feature = "xz"))]
use crate::pipeline_codec::PipelineCodec;
#[cfg(any(feature = "zstd", feature = "xz"))]
use libarchive_oxide_core::filter::FilterId;

#[cfg(feature = "gzip")]
use crate::deflate64::{InflateResult, InflaterManaged};

const LOCAL_SIGNATURE: u32 = 0x0403_4b50;
const CENTRAL_SIGNATURE: u32 = 0x0201_4b50;
const DESCRIPTOR_SIGNATURE: u32 = 0x0807_4b50;
const EOCD_SIGNATURE: u32 = 0x0605_4b50;
const ZIP64_EOCD_SIGNATURE: u32 = 0x0606_4b50;
const ZIP64_LOCATOR_SIGNATURE: u32 = 0x0706_4b50;
const DIGITAL_SIGNATURE: u32 = 0x0505_4b50;
const ARCHIVE_EXTRA_SIGNATURE: u32 = 0x0806_4b50;
const U16_SENTINEL: u16 = u16::MAX;
const U32_SENTINEL: u32 = u32::MAX;

#[derive(Debug, Clone, Copy)]
enum RecordKind {
    Local,
    Central,
    Eocd,
    Zip64Eocd,
    Zip64Locator,
    DigitalSignature,
    ArchiveExtra,
}

#[derive(Debug, Clone, Copy)]
enum HeaderPhase {
    Signature,
    Fixed(RecordKind),
    Complete(RecordKind),
}

#[derive(Debug)]
struct HeaderState {
    bytes: Vec<u8>,
    target: usize,
    phase: HeaderPhase,
    record_total: Option<u64>,
}

impl HeaderState {
    fn new() -> Self {
        Self {
            bytes: Vec::with_capacity(30),
            target: 4,
            phase: HeaderPhase::Signature,
            record_total: None,
        }
    }
}

#[derive(Debug)]
struct StoredKnown {
    remaining: u64,
    expected_crc: u32,
    crc: Crc32,
    produced: u64,
    expected_size: u64,
}

#[derive(Debug)]
struct StoredDescriptor {
    buffer: Vec<u8>,
    zip64: bool,
    crc: Crc32,
    produced: u64,
}

#[cfg(feature = "aes")]
#[derive(Debug)]
struct ZipCryptoStored {
    encrypted_remaining: Option<u64>,
    descriptor: bool,
    zip64: bool,
    buffer: Vec<u8>,
    header: [u8; 12],
    header_len: usize,
    decoder: Option<ZipCrypto>,
    verifier: u8,
    expected_crc: Option<u32>,
    crc: Crc32,
    produced: u64,
    expected_size: Option<u64>,
}

#[cfg(feature = "aes")]
#[derive(Debug)]
struct AesStored {
    encrypted_remaining: Option<u64>,
    descriptor: bool,
    zip64: bool,
    buffer: Vec<u8>,
    framing: Vec<u8>,
    framing_len: usize,
    salt_len: usize,
    strength: u8,
    decoder: Option<ZipAesDecoder>,
    produced: u64,
    expected_size: Option<u64>,
}

#[cfg(feature = "aes")]
#[derive(Debug)]
struct AesAuthentication {
    decoder: ZipAesDecoder,
    bytes: Vec<u8>,
    produced: u64,
    next: AesAuthenticationNext,
}

#[cfg(feature = "aes")]
#[derive(Debug)]
enum AesAuthenticationNext {
    EndEntry { expected_size: u64 },
    Descriptor { zip64: bool, compressed: u64 },
}

#[cfg(feature = "aes")]
#[derive(Debug)]
struct AesDeflate {
    compressed_remaining: Option<u64>,
    compressed: u64,
    descriptor: bool,
    zip64: bool,
    framing: Vec<u8>,
    framing_len: usize,
    salt_len: usize,
    strength: u8,
    crypto: Option<ZipAesDecoder>,
    decoder: RawInflateDecoder,
    produced: u64,
    expected_size: Option<u64>,
}

#[cfg(all(feature = "aes", feature = "gzip"))]
#[derive(Debug)]
struct AesDeflate64 {
    compressed_remaining: Option<u64>,
    compressed: u64,
    loaded: u64,
    descriptor: bool,
    zip64: bool,
    framing: Vec<u8>,
    framing_len: usize,
    salt_len: usize,
    strength: u8,
    crypto: Option<ZipAesDecoder>,
    decoder: Box<InflaterManaged>,
    produced: u64,
    expected_size: Option<u64>,
}

#[cfg(all(
    feature = "aes",
    any(feature = "bzip2", feature = "zstd", feature = "xz", feature = "ppmd")
))]
#[derive(Debug)]
struct AesPipeline {
    name: &'static str,
    compressed_remaining: Option<u64>,
    compressed: u64,
    descriptor: bool,
    zip64: bool,
    framing: Vec<u8>,
    framing_len: usize,
    salt_len: usize,
    strength: u8,
    crypto: Option<ZipAesDecoder>,
    decoder: EncryptedPipelineDecoder,
    boundary: PipelineBoundary,
    produced: u64,
    expected_size: Option<u64>,
}

#[cfg(all(feature = "aes", feature = "xz"))]
#[derive(Debug)]
struct AesXzPadding {
    crypto: ZipAesDecoder,
    bytes: Vec<u8>,
    zip64: bool,
    framing_len: usize,
    compressed: u64,
    produced: u64,
}

#[cfg(feature = "aes")]
#[derive(Debug)]
struct ZipCryptoDeflate {
    compressed_remaining: Option<u64>,
    compressed: u64,
    descriptor: bool,
    zip64: bool,
    header: [u8; 12],
    header_len: usize,
    crypto: Option<ZipCrypto>,
    verifier: u8,
    decoder: RawInflateDecoder,
    expected_crc: Option<u32>,
    crc: Crc32,
    produced: u64,
    expected_size: Option<u64>,
}

#[cfg(all(feature = "aes", feature = "gzip"))]
#[derive(Debug)]
struct ZipCryptoDeflate64 {
    compressed_remaining: Option<u64>,
    compressed: u64,
    loaded: u64,
    descriptor: bool,
    zip64: bool,
    header: [u8; 12],
    header_len: usize,
    crypto: Option<ZipCrypto>,
    verifier: u8,
    decoder: Box<InflaterManaged>,
    expected_crc: Option<u32>,
    crc: Crc32,
    produced: u64,
    expected_size: Option<u64>,
}

#[cfg(all(
    feature = "aes",
    any(feature = "bzip2", feature = "zstd", feature = "xz", feature = "ppmd")
))]
#[derive(Debug)]
struct ZipCryptoPipeline {
    name: &'static str,
    compressed_remaining: Option<u64>,
    compressed: u64,
    descriptor: bool,
    zip64: bool,
    header: [u8; 12],
    header_len: usize,
    crypto: Option<ZipCrypto>,
    verifier: u8,
    decoder: EncryptedPipelineDecoder,
    boundary: PipelineBoundary,
    expected_crc: Option<u32>,
    crc: Crc32,
    produced: u64,
    expected_size: Option<u64>,
}

#[cfg(all(feature = "aes", feature = "xz"))]
#[derive(Debug)]
struct ZipCryptoXzPadding {
    crypto: ZipCrypto,
    bytes: Vec<u8>,
    zip64: bool,
    crc: u32,
    compressed: u64,
    uncompressed: u64,
}

#[cfg(all(
    feature = "aes",
    any(feature = "bzip2", feature = "zstd", feature = "xz", feature = "ppmd")
))]
enum EncryptedPipelineDecoder {
    #[cfg(feature = "bzip2")]
    Bzip2(bzip2::Decompress),
    #[cfg(feature = "xz")]
    Lzma(EncryptedLzmaDecoder),
    #[cfg(feature = "ppmd")]
    Ppmd(EncryptedPpmdDecoder),
    #[cfg(any(feature = "zstd", feature = "xz"))]
    Codec(PipelineCodec),
}

#[cfg(all(feature = "aes", feature = "xz"))]
struct EncryptedLzmaDecoder {
    decoder: Option<Box<LzipDecoder>>,
    header: [u8; 9],
    header_len: usize,
    descriptor: bool,
    end_marker: bool,
    expected_size: Option<u64>,
    tail: bool,
}

#[cfg(all(feature = "aes", feature = "ppmd"))]
struct EncryptedPpmdDecoder {
    decoder: Option<Box<LzipDecoder>>,
    header: [u8; 2],
    header_len: usize,
    descriptor: bool,
    expected_size: Option<u64>,
    tail: bool,
}

#[cfg(all(feature = "aes", feature = "ppmd"))]
impl core::fmt::Debug for EncryptedPpmdDecoder {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("EncryptedPpmdDecoder")
            .field("decoder", &self.decoder)
            .field("header", &self.header)
            .field("header_len", &self.header_len)
            .field("descriptor", &self.descriptor)
            .field("expected_size", &self.expected_size)
            .field("tail", &self.tail)
            .finish()
    }
}

#[cfg(all(feature = "aes", feature = "xz"))]
impl core::fmt::Debug for EncryptedLzmaDecoder {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("EncryptedLzmaDecoder")
            .field("decoder", &self.decoder)
            .field("header", &self.header)
            .field("header_len", &self.header_len)
            .field("descriptor", &self.descriptor)
            .field("end_marker", &self.end_marker)
            .field("expected_size", &self.expected_size)
            .field("tail", &self.tail)
            .finish()
    }
}

#[cfg(all(
    feature = "aes",
    any(feature = "bzip2", feature = "zstd", feature = "xz", feature = "ppmd")
))]
impl core::fmt::Debug for EncryptedPipelineDecoder {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            #[cfg(feature = "bzip2")]
            Self::Bzip2(_) => formatter.write_str("Bzip2(..)"),
            #[cfg(feature = "xz")]
            Self::Lzma(decoder) => formatter.debug_tuple("Lzma").field(decoder).finish(),
            #[cfg(feature = "ppmd")]
            Self::Ppmd(decoder) => formatter.debug_tuple("Ppmd").field(decoder).finish(),
            #[cfg(any(feature = "zstd", feature = "xz"))]
            Self::Codec(codec) => formatter.debug_tuple("Codec").field(codec).finish(),
        }
    }
}

#[cfg(all(feature = "aes", feature = "xz"))]
impl EncryptedLzmaDecoder {
    fn new(
        descriptor: bool,
        end_marker: bool,
        expected_size: Option<u64>,
        encoded_size: Option<u64>,
    ) -> Result<Self, ArchiveError> {
        if encoded_size.is_some_and(|size| size < 9) {
            return Err(ZipStreamDecoder::error(
                ErrorKind::Malformed,
                "encrypted ZIP LZMA member is shorter than its 9-byte header",
            ));
        }
        if descriptor && !end_marker {
            return Err(ZipStreamDecoder::error(
                ErrorKind::Unsupported,
                "encrypted ZIP LZMA descriptors require an EOS marker",
            ));
        }
        Ok(Self {
            decoder: None,
            header: [0; 9],
            header_len: 0,
            descriptor,
            end_marker,
            expected_size,
            tail: false,
        })
    }

    fn process(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        end: EndOfInput,
        limits: Limits,
    ) -> Result<libarchive_oxide_core::CodecStep, ArchiveError> {
        if self.tail {
            return Ok(libarchive_oxide_core::CodecStep {
                consumed: input.len(),
                produced: 0,
                status: if matches!(end, EndOfInput::End) {
                    CodecStatus::Done
                } else {
                    CodecStatus::NeedInput
                },
            });
        }
        if self.decoder.is_none() {
            let count = (self.header.len() - self.header_len).min(input.len());
            self.header[self.header_len..self.header_len + count].copy_from_slice(&input[..count]);
            self.header_len += count;
            if self.header_len != self.header.len() {
                if matches!(end, EndOfInput::End) && count == input.len() {
                    return Err(ZipStreamDecoder::error(
                        ErrorKind::Malformed,
                        "truncated encrypted ZIP LZMA header",
                    ));
                }
                return Ok(libarchive_oxide_core::CodecStep {
                    consumed: count,
                    produced: 0,
                    status: CodecStatus::NeedInput,
                });
            }
            if u16::from_le_bytes([self.header[2], self.header[3]]) != 5 {
                return Err(ZipStreamDecoder::error(
                    ErrorKind::Malformed,
                    "encrypted ZIP LZMA property size is not 5",
                ));
            }
            let properties = self.header[4];
            let dictionary = u32::from_le_bytes(self.header[5..9].try_into().map_err(|_| {
                ZipStreamDecoder::error(ErrorKind::Protocol, "encrypted ZIP LZMA header vanished")
            })?);
            self.decoder = Some(Box::new(if self.descriptor {
                LzipDecoder::new_zip_lzma_checkpointed(limits, properties, dictionary)?
            } else {
                let declared_size = if self.end_marker {
                    u64::MAX
                } else {
                    self.expected_size.ok_or_else(|| {
                        ZipStreamDecoder::error(
                            ErrorKind::Protocol,
                            "encrypted known-size ZIP LZMA entry lost its decoded size",
                        )
                    })?
                };
                LzipDecoder::new_zip_lzma(limits, properties, dictionary, declared_size)?
            }));
            return Ok(libarchive_oxide_core::CodecStep {
                consumed: count,
                produced: 0,
                status: CodecStatus::NeedInput,
            });
        }
        let mut step = self
            .decoder
            .as_mut()
            .ok_or_else(|| {
                ZipStreamDecoder::error(
                    ErrorKind::Protocol,
                    "encrypted ZIP LZMA decoder disappeared",
                )
            })?
            .process(input, output, end)?;
        if step.status == CodecStatus::Done && !self.descriptor {
            self.tail = true;
            step.consumed = input.len();
            step.status = if matches!(end, EndOfInput::End) {
                CodecStatus::Done
            } else {
                CodecStatus::NeedInput
            };
        }
        Ok(step)
    }
}

#[cfg(all(feature = "aes", feature = "ppmd"))]
impl EncryptedPpmdDecoder {
    fn new(
        descriptor: bool,
        expected_size: Option<u64>,
        encoded_size: Option<u64>,
    ) -> Result<Self, ArchiveError> {
        if encoded_size.is_some_and(|size| size < 6) {
            return Err(ZipStreamDecoder::error(
                ErrorKind::Malformed,
                "encrypted ZIP PPMd member is shorter than its parameter and range headers",
            ));
        }
        Ok(Self {
            decoder: None,
            header: [0; 2],
            header_len: 0,
            descriptor,
            expected_size,
            tail: false,
        })
    }

    fn process(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        end: EndOfInput,
        limits: Limits,
    ) -> Result<libarchive_oxide_core::CodecStep, ArchiveError> {
        if self.tail {
            return Ok(libarchive_oxide_core::CodecStep {
                consumed: input.len(),
                produced: 0,
                status: if matches!(end, EndOfInput::End) {
                    CodecStatus::Done
                } else {
                    CodecStatus::NeedInput
                },
            });
        }
        if self.decoder.is_none() {
            let count = (self.header.len() - self.header_len).min(input.len());
            self.header[self.header_len..self.header_len + count].copy_from_slice(&input[..count]);
            self.header_len += count;
            if self.header_len != self.header.len() {
                if matches!(end, EndOfInput::End) && count == input.len() {
                    return Err(ZipStreamDecoder::error(
                        ErrorKind::Malformed,
                        "truncated encrypted ZIP PPMd parameter header",
                    ));
                }
                return Ok(libarchive_oxide_core::CodecStep {
                    consumed: count,
                    produced: 0,
                    status: CodecStatus::NeedInput,
                });
            }
            let parameters = u16::from_le_bytes(self.header);
            self.decoder = Some(Box::new(if self.descriptor {
                LzipDecoder::new_zip_ppmd_checkpointed(limits, parameters)?
            } else {
                let declared_size = self.expected_size.ok_or_else(|| {
                    ZipStreamDecoder::error(
                        ErrorKind::Protocol,
                        "encrypted known-size ZIP PPMd entry lost its decoded size",
                    )
                })?;
                LzipDecoder::new_zip_ppmd(limits, parameters, declared_size)?
            }));
            return Ok(libarchive_oxide_core::CodecStep {
                consumed: count,
                produced: 0,
                status: CodecStatus::NeedInput,
            });
        }
        let mut step = self
            .decoder
            .as_mut()
            .ok_or_else(|| {
                ZipStreamDecoder::error(
                    ErrorKind::Protocol,
                    "encrypted ZIP PPMd decoder disappeared",
                )
            })?
            .process(input, output, end)?;
        if step.status == CodecStatus::Done && !self.descriptor {
            self.tail = true;
            step.consumed = input.len();
            step.status = if matches!(end, EndOfInput::End) {
                CodecStatus::Done
            } else {
                CodecStatus::NeedInput
            };
        }
        Ok(step)
    }
}

#[derive(Debug)]
struct DeflateState {
    decoder: RawInflateDecoder,
    compressed_remaining: Option<u64>,
    compressed: u64,
    produced: u64,
    crc: Crc32,
    expected_crc: Option<u32>,
    expected_size: Option<u64>,
    descriptor: bool,
    zip64: bool,
}

#[cfg(feature = "gzip")]
#[derive(Debug)]
struct Deflate64State {
    decoder: Box<InflaterManaged>,
    compressed_remaining: Option<u64>,
    compressed: u64,
    loaded: u64,
    produced: u64,
    crc: Crc32,
    expected_crc: Option<u32>,
    expected_size: Option<u64>,
    descriptor: bool,
    zip64: bool,
}

#[cfg(feature = "xz")]
#[derive(Debug)]
struct LzmaState {
    decoder: Option<Box<LzipDecoder>>,
    header: [u8; 9],
    header_len: usize,
    compressed_remaining: Option<u64>,
    compressed: u64,
    produced: u64,
    crc: Crc32,
    expected_crc: Option<u32>,
    expected_size: Option<u64>,
    end_marker: bool,
    descriptor: bool,
    zip64: bool,
}

#[cfg(feature = "ppmd")]
#[derive(Debug)]
struct PpmdState {
    decoder: Option<Box<LzipDecoder>>,
    header: [u8; 2],
    header_len: usize,
    compressed_remaining: Option<u64>,
    compressed: u64,
    produced: u64,
    crc: Crc32,
    expected_crc: Option<u32>,
    expected_size: Option<u64>,
    descriptor: bool,
    zip64: bool,
}

#[cfg(any(feature = "zstd", feature = "xz"))]
#[derive(Debug)]
struct PipelineState {
    name: &'static str,
    decoder: PipelineCodec,
    boundary: PipelineBoundary,
    compressed_remaining: Option<u64>,
    compressed: u64,
    produced: u64,
    crc: Crc32,
    expected_crc: Option<u32>,
    expected_size: Option<u64>,
    descriptor: bool,
    zip64: bool,
}

#[cfg(any(
    feature = "zstd",
    feature = "xz",
    all(feature = "aes", any(feature = "bzip2", feature = "ppmd"))
))]
#[derive(Debug)]
enum PipelineBoundary {
    Known,
    #[cfg(all(
        feature = "aes",
        any(feature = "bzip2", feature = "xz", feature = "ppmd")
    ))]
    Codec,
    #[cfg(feature = "zstd")]
    Zstd(ZstdBoundary),
    #[cfg(feature = "xz")]
    Xz(XzStreamBoundary),
}

#[cfg(any(
    feature = "zstd",
    feature = "xz",
    all(feature = "aes", any(feature = "bzip2", feature = "ppmd"))
))]
impl PipelineBoundary {
    #[cfg(any(feature = "zstd", feature = "xz"))]
    fn preview(&self, input: &[u8]) -> Result<(usize, bool), ArchiveError> {
        match self {
            Self::Known => Err(ZipStreamDecoder::error(
                ErrorKind::Protocol,
                "known-size ZIP pipeline requested intrinsic boundary detection",
            )),
            #[cfg(all(
                feature = "aes",
                any(feature = "bzip2", feature = "xz", feature = "ppmd")
            ))]
            Self::Codec => Ok((input.len(), false)),
            #[cfg(feature = "zstd")]
            Self::Zstd(boundary) => boundary.preview(input),
            #[cfg(feature = "xz")]
            Self::Xz(boundary) => boundary.preview(input),
        }
    }

    fn consume(&mut self, input: &[u8]) -> Result<usize, ArchiveError> {
        match self {
            Self::Known => Err(ZipStreamDecoder::error(
                ErrorKind::Protocol,
                "known-size ZIP pipeline advanced an intrinsic boundary",
            )),
            #[cfg(all(
                feature = "aes",
                any(feature = "bzip2", feature = "xz", feature = "ppmd")
            ))]
            Self::Codec => Ok(input.len()),
            #[cfg(feature = "zstd")]
            Self::Zstd(boundary) => boundary.consume(input),
            #[cfg(feature = "xz")]
            Self::Xz(boundary) => boundary.consume(input),
        }
    }

    const fn done(&self) -> bool {
        match self {
            Self::Known => false,
            #[cfg(all(
                feature = "aes",
                any(feature = "bzip2", feature = "xz", feature = "ppmd")
            ))]
            Self::Codec => false,
            #[cfg(feature = "zstd")]
            Self::Zstd(boundary) => boundary.done(),
            #[cfg(feature = "xz")]
            Self::Xz(boundary) => boundary.done(),
        }
    }

    #[cfg(feature = "aes")]
    fn preview_encrypted(&self, input: &[u8]) -> Result<(usize, bool), ArchiveError> {
        match self {
            Self::Known => Err(ZipStreamDecoder::error(
                ErrorKind::Protocol,
                "known-size encrypted ZIP pipeline requested intrinsic boundary detection",
            )),
            #[cfg(any(feature = "bzip2", feature = "xz", feature = "ppmd"))]
            Self::Codec => Ok((input.len(), false)),
            #[cfg(feature = "zstd")]
            Self::Zstd(boundary) => boundary.preview(input),
            #[cfg(feature = "xz")]
            Self::Xz(boundary) => boundary.preview_intrinsic(input),
        }
    }

    #[cfg(feature = "aes")]
    const fn requires_structural_end(&self) -> bool {
        match self {
            Self::Known => false,
            #[cfg(any(feature = "bzip2", feature = "xz", feature = "ppmd"))]
            Self::Codec => false,
            #[cfg(feature = "zstd")]
            Self::Zstd(_) => true,
            #[cfg(feature = "xz")]
            Self::Xz(_) => true,
        }
    }
}

#[cfg(feature = "zstd")]
#[derive(Clone, Debug)]
struct ZstdBoundary {
    phase: ZstdBoundaryPhase,
    header: [u8; 18],
    header_len: usize,
    target: usize,
    checksum: bool,
}

#[cfg(feature = "zstd")]
#[derive(Clone, Copy, Debug)]
enum ZstdBoundaryPhase {
    FrameHeader,
    BlockHeader,
    BlockData { remaining: u32, last: bool },
    Checksum(u8),
    Done,
}

#[cfg(feature = "zstd")]
impl ZstdBoundary {
    const fn new() -> Self {
        Self {
            phase: ZstdBoundaryPhase::FrameHeader,
            header: [0; 18],
            header_len: 0,
            target: 5,
            checksum: false,
        }
    }

    const fn done(&self) -> bool {
        matches!(self.phase, ZstdBoundaryPhase::Done)
    }

    fn preview(&self, input: &[u8]) -> Result<(usize, bool), ArchiveError> {
        let mut next = self.clone();
        let consumed = next.consume(input)?;
        Ok((consumed, next.done()))
    }

    #[allow(clippy::too_many_lines)]
    fn consume(&mut self, input: &[u8]) -> Result<usize, ArchiveError> {
        let mut consumed = 0;
        while consumed < input.len() && !self.done() {
            match self.phase {
                ZstdBoundaryPhase::FrameHeader => {
                    let count = (self.target - self.header_len).min(input.len() - consumed);
                    self.header[self.header_len..self.header_len + count]
                        .copy_from_slice(&input[consumed..consumed + count]);
                    self.header_len += count;
                    consumed += count;
                    if self.header_len < self.target {
                        continue;
                    }
                    if self.target == 5 {
                        if self.header[..4] != [0x28, 0xb5, 0x2f, 0xfd] {
                            return Err(ZipStreamDecoder::error(
                                ErrorKind::Malformed,
                                "invalid ZIP Zstandard frame magic",
                            ));
                        }
                        let descriptor = self.header[4];
                        if descriptor & 0x08 != 0 {
                            return Err(ZipStreamDecoder::error(
                                ErrorKind::Malformed,
                                "ZIP Zstandard frame uses its reserved descriptor bit",
                            ));
                        }
                        let single_segment = descriptor & 0x20 != 0;
                        let dictionary = [0_usize, 1, 2, 4][usize::from(descriptor & 0x03)];
                        let content_size = match descriptor >> 6 {
                            0 if single_segment => 1,
                            0 => 0,
                            1 => 2,
                            2 => 4,
                            3 => 8,
                            _ => {
                                return Err(ZipStreamDecoder::error(
                                    ErrorKind::Protocol,
                                    "ZIP Zstandard content-size flag escaped its bit field",
                                ));
                            },
                        };
                        self.checksum = descriptor & 0x04 != 0;
                        self.target = 5 + usize::from(!single_segment) + dictionary + content_size;
                        continue;
                    }
                    self.header_len = 0;
                    self.target = 3;
                    self.phase = ZstdBoundaryPhase::BlockHeader;
                },
                ZstdBoundaryPhase::BlockHeader => {
                    let count = (3 - self.header_len).min(input.len() - consumed);
                    self.header[self.header_len..self.header_len + count]
                        .copy_from_slice(&input[consumed..consumed + count]);
                    self.header_len += count;
                    consumed += count;
                    if self.header_len != 3 {
                        continue;
                    }
                    let block = u32::from(self.header[0])
                        | u32::from(self.header[1]) << 8
                        | u32::from(self.header[2]) << 16;
                    let last = block & 1 != 0;
                    let kind = (block >> 1) & 0x03;
                    if kind == 3 {
                        return Err(ZipStreamDecoder::error(
                            ErrorKind::Malformed,
                            "ZIP Zstandard frame uses a reserved block type",
                        ));
                    }
                    let declared = block >> 3;
                    let remaining = if kind == 1 { 1 } else { declared };
                    self.header_len = 0;
                    self.phase = ZstdBoundaryPhase::BlockData { remaining, last };
                    self.finish_empty_block();
                },
                ZstdBoundaryPhase::BlockData { remaining, last } => {
                    let count = usize::try_from(remaining)
                        .unwrap_or(usize::MAX)
                        .min(input.len() - consumed);
                    consumed += count;
                    let remaining = remaining - u32::try_from(count).unwrap_or(remaining);
                    self.phase = ZstdBoundaryPhase::BlockData { remaining, last };
                    self.finish_empty_block();
                },
                ZstdBoundaryPhase::Checksum(remaining) => {
                    let count = usize::from(remaining).min(input.len() - consumed);
                    consumed += count;
                    let remaining = remaining - u8::try_from(count).unwrap_or(remaining);
                    self.phase = if remaining == 0 {
                        ZstdBoundaryPhase::Done
                    } else {
                        ZstdBoundaryPhase::Checksum(remaining)
                    };
                },
                ZstdBoundaryPhase::Done => {},
            }
        }
        Ok(consumed)
    }

    fn finish_empty_block(&mut self) {
        let ZstdBoundaryPhase::BlockData { remaining: 0, last } = self.phase else {
            return;
        };
        self.phase = if last {
            if self.checksum {
                ZstdBoundaryPhase::Checksum(4)
            } else {
                ZstdBoundaryPhase::Done
            }
        } else {
            ZstdBoundaryPhase::BlockHeader
        };
    }
}

#[cfg(feature = "bzip2")]
struct Bzip2State {
    decoder: bzip2::Decompress,
    compressed_remaining: Option<u64>,
    compressed: u64,
    produced: u64,
    crc: Crc32,
    expected_crc: Option<u32>,
    expected_size: Option<u64>,
    descriptor: bool,
    zip64: bool,
}

#[cfg(feature = "bzip2")]
impl core::fmt::Debug for Bzip2State {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Bzip2State")
            .field("compressed_remaining", &self.compressed_remaining)
            .field("compressed", &self.compressed)
            .field("produced", &self.produced)
            .field("descriptor", &self.descriptor)
            .field("zip64", &self.zip64)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
struct DescriptorState {
    bytes: Vec<u8>,
    zip64: bool,
    crc: u32,
    compressed: u64,
    uncompressed: u64,
}

#[derive(Debug)]
enum State {
    Header(HeaderState),
    StoredKnown(StoredKnown),
    StoredDescriptor(StoredDescriptor),
    #[cfg(feature = "aes")]
    AesStored(AesStored),
    #[cfg(feature = "aes")]
    AesAuthentication(AesAuthentication),
    #[cfg(feature = "aes")]
    AesDeflate(AesDeflate),
    #[cfg(all(feature = "aes", feature = "gzip"))]
    AesDeflate64(AesDeflate64),
    #[cfg(all(
        feature = "aes",
        any(feature = "bzip2", feature = "zstd", feature = "xz", feature = "ppmd")
    ))]
    AesPipeline(AesPipeline),
    #[cfg(all(feature = "aes", feature = "xz"))]
    AesXzPadding(AesXzPadding),
    #[cfg(feature = "aes")]
    ZipCryptoStored(ZipCryptoStored),
    #[cfg(feature = "aes")]
    ZipCryptoDeflate(ZipCryptoDeflate),
    #[cfg(all(feature = "aes", feature = "gzip"))]
    ZipCryptoDeflate64(ZipCryptoDeflate64),
    #[cfg(all(
        feature = "aes",
        any(feature = "bzip2", feature = "zstd", feature = "xz", feature = "ppmd")
    ))]
    ZipCryptoPipeline(ZipCryptoPipeline),
    #[cfg(all(feature = "aes", feature = "xz"))]
    ZipCryptoXzPadding(ZipCryptoXzPadding),
    Deflate(DeflateState),
    #[cfg(feature = "gzip")]
    Deflate64(Deflate64State),
    #[cfg(feature = "xz")]
    Lzma(LzmaState),
    #[cfg(feature = "xz")]
    LzmaTail(u64),
    #[cfg(feature = "ppmd")]
    Ppmd(PpmdState),
    #[cfg(feature = "ppmd")]
    PpmdTail(u64),
    #[cfg(any(feature = "zstd", feature = "xz"))]
    Pipeline(PipelineState),
    #[cfg(feature = "bzip2")]
    Bzip2(Bzip2State),
    Descriptor(DescriptorState),
    EndEntry,
    Skip(u64),
    Done,
    Poisoned,
}

/// Incremental ZIP decoder for forward-only inputs.
///
/// Entry bodies are emitted from local headers.
/// Central-directory and end records are then parsed without retaining payload bytes.
#[derive(Debug)]
pub(crate) struct ZipStreamDecoder {
    limits: Limits,
    state: State,
    entries: u64,
    central_entries: u64,
    decoded: u64,
    metadata: usize,
    saw_central: bool,
    zip64_entries: Option<u64>,
    #[cfg(feature = "aes")]
    passwords: Vec<SecretBytes>,
}

impl ZipStreamDecoder {
    pub(crate) fn with_passwords(limits: Limits, passwords: Vec<crate::SecretBytes>) -> Self {
        #[cfg(not(feature = "aes"))]
        drop(passwords);
        Self {
            limits,
            state: State::Header(HeaderState {
                bytes: Vec::new(),
                target: 4,
                phase: HeaderPhase::Signature,
                record_total: None,
            }),
            entries: 0,
            central_entries: 0,
            decoded: 0,
            metadata: 0,
            saw_central: false,
            zip64_entries: None,
            #[cfg(feature = "aes")]
            passwords,
        }
    }

    fn error(kind: ErrorKind, context: impl Into<String>) -> ArchiveError {
        ArchiveError::new(kind)
            .with_format("zip")
            .with_context(context)
    }

    fn need_input(consumed: usize) -> DecodeStep<'static> {
        DecodeStep {
            consumed,
            produced: 0,
            event: DecodeEvent::NeedInput,
        }
    }

    fn account_metadata(&mut self, amount: usize) -> Result<(), ArchiveError> {
        self.metadata = self
            .metadata
            .checked_add(amount)
            .ok_or_else(|| Self::error(ErrorKind::Limit, "ZIP metadata accounting overflow"))?;
        if self
            .limits
            .metadata_bytes()
            .is_some_and(|limit| self.metadata > limit)
        {
            return Err(Self::error(
                ErrorKind::Limit,
                "ZIP metadata exceeds configured limit",
            ));
        }
        Ok(())
    }

    fn account_data(&mut self, amount: usize) -> Result<(), ArchiveError> {
        let amount = amount as u64;
        self.decoded = self
            .decoded
            .checked_add(amount)
            .ok_or_else(|| Self::error(ErrorKind::Limit, "ZIP decoded byte count overflow"))?;
        if self
            .limits
            .decoded_total()
            .is_some_and(|limit| self.decoded > limit)
        {
            return Err(Self::error(
                ErrorKind::Limit,
                "ZIP decoded bytes exceed configured limit",
            ));
        }
        Ok(())
    }

    fn finish_entry<'a>(&mut self, consumed: usize) -> DecodeStep<'a> {
        self.state = State::Header(HeaderState::new());
        DecodeStep {
            consumed,
            produced: 0,
            event: DecodeEvent::EndEntry,
        }
    }

    #[allow(clippy::too_many_lines)]
    fn step_header<'a>(
        &mut self,
        mut header: HeaderState,
        input: &'a [u8],
        end: EndOfInput,
    ) -> Result<DecodeStep<'a>, ArchiveError> {
        let mut consumed = 0;
        loop {
            let needed = header.target.saturating_sub(header.bytes.len());
            let available = input.len().saturating_sub(consumed);
            let count = needed.min(available);
            if count != 0 {
                header
                    .bytes
                    .extend_from_slice(&input[consumed..consumed + count]);
                consumed += count;
            }
            if header.bytes.len() < header.target {
                if matches!(end, EndOfInput::End) && consumed == input.len() {
                    return Err(Self::error(
                        ErrorKind::Malformed,
                        "truncated ZIP structural record",
                    ));
                }
                self.state = State::Header(header);
                return Ok(Self::need_input(consumed));
            }

            match header.phase {
                HeaderPhase::Signature => {
                    let signature = le32(&header.bytes, 0)?;
                    let (kind, fixed) = match signature {
                        LOCAL_SIGNATURE => (RecordKind::Local, 30),
                        CENTRAL_SIGNATURE => (RecordKind::Central, 46),
                        EOCD_SIGNATURE => (RecordKind::Eocd, 22),
                        ZIP64_EOCD_SIGNATURE => (RecordKind::Zip64Eocd, 12),
                        ZIP64_LOCATOR_SIGNATURE => (RecordKind::Zip64Locator, 20),
                        DIGITAL_SIGNATURE => (RecordKind::DigitalSignature, 6),
                        ARCHIVE_EXTRA_SIGNATURE => (RecordKind::ArchiveExtra, 8),
                        DESCRIPTOR_SIGNATURE => {
                            return Err(Self::error(
                                ErrorKind::Unsupported,
                                "split ZIP marker requires a VolumeSet reader",
                            ));
                        },
                        _ => {
                            return Err(Self::error(
                                ErrorKind::Malformed,
                                "unknown ZIP structural signature",
                            ));
                        },
                    };
                    header.phase = HeaderPhase::Fixed(kind);
                    header.target = fixed;
                },
                HeaderPhase::Fixed(RecordKind::Local) => {
                    let name = usize::from(le16(&header.bytes, 26)?);
                    let extra = usize::from(le16(&header.bytes, 28)?);
                    let variable = name.checked_add(extra).ok_or_else(|| {
                        Self::error(ErrorKind::Limit, "ZIP local metadata length overflow")
                    })?;
                    self.check_record_allocation(variable, "ZIP local metadata")?;
                    header.target = 30_usize.checked_add(variable).ok_or_else(|| {
                        Self::error(ErrorKind::Limit, "ZIP local header length overflow")
                    })?;
                    header.phase = HeaderPhase::Complete(RecordKind::Local);
                },
                HeaderPhase::Complete(RecordKind::Local) => {
                    return self.parse_local(&header.bytes, consumed);
                },
                HeaderPhase::Fixed(RecordKind::Central) => {
                    self.saw_central = true;
                    self.central_entries =
                        self.central_entries.checked_add(1).ok_or_else(|| {
                            Self::error(
                                ErrorKind::Limit,
                                "ZIP central-directory entry count overflow",
                            )
                        })?;
                    let variable = usize::from(le16(&header.bytes, 28)?)
                        .checked_add(usize::from(le16(&header.bytes, 30)?))
                        .and_then(|value| {
                            value.checked_add(usize::from(le16(&header.bytes, 32).ok()?))
                        })
                        .ok_or_else(|| {
                            Self::error(
                                ErrorKind::Limit,
                                "ZIP central-directory metadata length overflow",
                            )
                        })?;
                    self.account_metadata(46_usize.checked_add(variable).ok_or_else(|| {
                        Self::error(ErrorKind::Limit, "ZIP central metadata accounting overflow")
                    })?)?;
                    self.state = if variable == 0 {
                        State::Header(HeaderState::new())
                    } else {
                        State::Skip(variable as u64)
                    };
                    return Ok(Self::need_input(consumed));
                },
                HeaderPhase::Fixed(RecordKind::Eocd) => {
                    let comment = usize::from(le16(&header.bytes, 20)?);
                    self.check_record_allocation(comment, "ZIP archive comment")?;
                    header.target = 22_usize.checked_add(comment).ok_or_else(|| {
                        Self::error(ErrorKind::Limit, "ZIP end record length overflow")
                    })?;
                    header.phase = HeaderPhase::Complete(RecordKind::Eocd);
                },
                HeaderPhase::Complete(RecordKind::Eocd) => {
                    return self.parse_eocd(&header.bytes, consumed);
                },
                HeaderPhase::Fixed(RecordKind::Zip64Eocd) => {
                    let body = le64(&header.bytes, 4)?;
                    if body < 44 {
                        return Err(Self::error(
                            ErrorKind::Malformed,
                            "ZIP64 end record is shorter than its fixed fields",
                        ));
                    }
                    let total = body.checked_add(12).ok_or_else(|| {
                        Self::error(ErrorKind::Limit, "ZIP64 end record length overflow")
                    })?;
                    self.account_metadata(usize::try_from(total).map_err(|_| {
                        Self::error(ErrorKind::Limit, "ZIP64 end record exceeds address space")
                    })?)?;
                    header.record_total = Some(total);
                    header.target = 56;
                    header.phase = HeaderPhase::Complete(RecordKind::Zip64Eocd);
                },
                HeaderPhase::Complete(RecordKind::Zip64Eocd) => {
                    if le32(&header.bytes, 16)? != 0 || le32(&header.bytes, 20)? != 0 {
                        return Err(Self::error(
                            ErrorKind::Unsupported,
                            "multi-disk ZIP requires a VolumeSet reader",
                        ));
                    }
                    let on_disk = le64(&header.bytes, 24)?;
                    let total_entries = le64(&header.bytes, 32)?;
                    if on_disk != total_entries {
                        return Err(Self::error(
                            ErrorKind::Malformed,
                            "single-disk ZIP64 entry counts disagree",
                        ));
                    }
                    self.zip64_entries = Some(total_entries);
                    let total = header.record_total.ok_or_else(|| {
                        Self::error(ErrorKind::Protocol, "ZIP64 record length disappeared")
                    })?;
                    let remaining = total.checked_sub(56).ok_or_else(|| {
                        Self::error(ErrorKind::Malformed, "ZIP64 end record is truncated")
                    })?;
                    self.state = if remaining == 0 {
                        State::Header(HeaderState::new())
                    } else {
                        State::Skip(remaining)
                    };
                    return Ok(Self::need_input(consumed));
                },
                HeaderPhase::Fixed(RecordKind::Zip64Locator) => {
                    if le32(&header.bytes, 4)? != 0 || le32(&header.bytes, 16)? != 1 {
                        return Err(Self::error(
                            ErrorKind::Unsupported,
                            "multi-disk ZIP requires a VolumeSet reader",
                        ));
                    }
                    self.state = State::Header(HeaderState::new());
                    return Ok(Self::need_input(consumed));
                },
                HeaderPhase::Fixed(RecordKind::DigitalSignature) => {
                    let remaining = u64::from(le16(&header.bytes, 4)?);
                    let amount = usize::try_from(remaining).map_err(|_| {
                        Self::error(
                            ErrorKind::Limit,
                            "ZIP digital signature exceeds address space",
                        )
                    })?;
                    self.account_metadata(6_usize.checked_add(amount).ok_or_else(|| {
                        Self::error(ErrorKind::Limit, "ZIP digital signature length overflow")
                    })?)?;
                    self.state = if remaining == 0 {
                        State::Header(HeaderState::new())
                    } else {
                        State::Skip(remaining)
                    };
                    return Ok(Self::need_input(consumed));
                },
                HeaderPhase::Fixed(RecordKind::ArchiveExtra) => {
                    let remaining = u64::from(le32(&header.bytes, 4)?);
                    let amount = usize::try_from(remaining).map_err(|_| {
                        Self::error(ErrorKind::Limit, "ZIP archive extra exceeds address space")
                    })?;
                    self.account_metadata(8_usize.checked_add(amount).ok_or_else(|| {
                        Self::error(ErrorKind::Limit, "ZIP archive extra length overflow")
                    })?)?;
                    self.state = if remaining == 0 {
                        State::Header(HeaderState::new())
                    } else {
                        State::Skip(remaining)
                    };
                    return Ok(Self::need_input(consumed));
                },
                HeaderPhase::Complete(
                    RecordKind::Central
                    | RecordKind::Zip64Locator
                    | RecordKind::DigitalSignature
                    | RecordKind::ArchiveExtra,
                ) => {
                    return Err(Self::error(
                        ErrorKind::Protocol,
                        "ZIP record entered an invalid parser phase",
                    ));
                },
            }
        }
    }

    fn check_record_allocation(
        &self,
        amount: usize,
        context: &'static str,
    ) -> Result<(), ArchiveError> {
        if self
            .limits
            .metadata_bytes()
            .is_some_and(|limit| amount > limit)
            || self
                .limits
                .in_flight_bytes()
                .is_some_and(|limit| amount > limit)
        {
            return Err(Self::error(
                ErrorKind::Limit,
                format!("{context} exceeds configured buffer limit"),
            ));
        }
        Ok(())
    }

    #[cfg(feature = "gzip")]
    fn deflate64_decoder(&self) -> Result<Box<InflaterManaged>, ArchiveError> {
        let workspace = core::mem::size_of::<InflaterManaged>();
        if self
            .limits
            .codec_memory()
            .is_some_and(|limit| limit < workspace)
        {
            return Err(Self::error(
                ErrorKind::Limit,
                "ZIP Deflate64 decoder exceeds the configured codec-memory budget",
            ));
        }
        Ok(Box::new(InflaterManaged::new()))
    }

    #[cfg(feature = "gzip")]
    fn deflate64_descriptor_consumed(
        decoder: &InflaterManaged,
        committed_before: u64,
        loaded: u64,
    ) -> Result<usize, ArchiveError> {
        let checkpoint = decoder.checkpoint_input_bytes().unwrap_or(committed_before);
        if decoder.finished() && decoder.finished_input_bytes() != Some(checkpoint) {
            return Err(Self::error(
                ErrorKind::Protocol,
                "finished ZIP Deflate64 checkpoint disagrees with its stream boundary",
            ));
        }
        if checkpoint > loaded {
            return Err(Self::error(
                ErrorKind::Protocol,
                "ZIP Deflate64 checkpoint exceeds loaded input",
            ));
        }
        let committed = checkpoint.checked_sub(committed_before).ok_or_else(|| {
            Self::error(
                ErrorKind::Protocol,
                "ZIP Deflate64 checkpoint moved backwards",
            )
        })?;
        usize::try_from(committed).map_err(|_| {
            Self::error(
                ErrorKind::Limit,
                "ZIP Deflate64 committed input exceeds address space",
            )
        })
    }

    #[allow(clippy::too_many_lines)]
    fn parse_local<'a>(
        &mut self,
        header: &[u8],
        consumed: usize,
    ) -> Result<DecodeStep<'a>, ArchiveError> {
        if self.saw_central {
            return Err(Self::error(
                ErrorKind::Malformed,
                "ZIP local header appears after the central directory",
            ));
        }
        let flags = le16(header, 6)?;
        let encrypted = flags & 0x0001 != 0;
        #[cfg(not(feature = "aes"))]
        if encrypted {
            return Err(Self::error(
                ErrorKind::Unsupported,
                "encrypted ZIP entries require the aes feature",
            ));
        }
        if flags & 0x2040 != 0 {
            return Err(Self::error(
                ErrorKind::Unsupported,
                "ZIP entry uses unsupported strong-encryption flags",
            ));
        }
        let method = le16(header, 8)?;
        if !(matches!(method, 0 | 8)
            || cfg!(feature = "aes") && method == 99
            || cfg!(feature = "gzip") && method == 9
            || cfg!(feature = "bzip2") && method == 12
            || cfg!(feature = "xz") && method == 14
            || cfg!(feature = "zstd") && method == 93
            || cfg!(feature = "xz") && method == 95
            || cfg!(feature = "ppmd") && method == 98)
        {
            return Err(Self::error(
                ErrorKind::Unsupported,
                format!("ZIP method {method} is not available in the forward-only reader"),
            ));
        }
        let expected_crc = le32(header, 14)?;
        let compressed32 = le32(header, 18)?;
        let uncompressed32 = le32(header, 22)?;
        let name_length = usize::from(le16(header, 26)?);
        let extra_length = usize::from(le16(header, 28)?);
        let raw_name = header
            .get(30..30 + name_length)
            .ok_or_else(|| Self::error(ErrorKind::Malformed, "truncated ZIP local pathname"))?;
        if raw_name.is_empty() {
            return Err(Self::error(
                ErrorKind::Malformed,
                "ZIP entry pathname is empty",
            ));
        }
        if self
            .limits
            .path_bytes()
            .is_some_and(|limit| raw_name.len() > limit)
        {
            return Err(Self::error(
                ErrorKind::Limit,
                "ZIP pathname exceeds configured limit",
            ));
        }
        let extra = header
            .get(30 + name_length..30 + name_length + extra_length)
            .ok_or_else(|| Self::error(ErrorKind::Malformed, "truncated ZIP local extra fields"))?;
        validate_extra_fields(extra)?;
        #[cfg(feature = "aes")]
        let aes = local_aes_parameters(extra, method)?;
        #[cfg(feature = "aes")]
        if aes.is_some() && !encrypted {
            return Err(Self::error(
                ErrorKind::Malformed,
                "WinZip AES method is missing the encrypted flag",
            ));
        }
        #[cfg(feature = "aes")]
        let payload_method = aes.map_or(method, |parameters| parameters.method);
        #[cfg(not(feature = "aes"))]
        let payload_method = method;
        if !(matches!(payload_method, 0 | 8)
            || cfg!(feature = "gzip") && payload_method == 9
            || cfg!(feature = "bzip2") && payload_method == 12
            || cfg!(feature = "xz") && payload_method == 14
            || cfg!(feature = "zstd") && payload_method == 93
            || cfg!(feature = "xz") && payload_method == 95
            || cfg!(feature = "ppmd") && payload_method == 98)
        {
            return Err(Self::error(
                ErrorKind::Unsupported,
                format!("ZIP method {payload_method} is not available in the forward-only reader"),
            ));
        }
        let name = unicode_zip_value(extra, 0x7075, raw_name)?.unwrap_or(raw_name);
        if self
            .limits
            .path_bytes()
            .is_some_and(|limit| name.len() > limit)
        {
            return Err(Self::error(
                ErrorKind::Limit,
                "ZIP Unicode pathname exceeds configured limit",
            ));
        }
        let encoding = if flags & 0x0800 != 0 || core::str::from_utf8(name).is_ok() {
            PathEncoding::Utf8
        } else {
            PathEncoding::Bytes
        };
        let path = ArchivePath::try_from_encoded(name.to_vec(), encoding)?;
        let descriptor = flags & 0x0008 != 0;
        if payload_method == 14 && descriptor && flags & 0x0002 == 0 {
            return Err(Self::error(
                ErrorKind::Unsupported,
                "forward-only ZIP LZMA descriptors require an EOS marker",
            ));
        }
        let encrypted_method = matches!(payload_method, 0 | 8)
            || cfg!(feature = "bzip2") && payload_method == 12
            || cfg!(feature = "xz") && payload_method == 14
            || cfg!(feature = "zstd") && payload_method == 93
            || cfg!(feature = "xz") && payload_method == 95
            || cfg!(feature = "ppmd") && payload_method == 98;
        #[cfg(feature = "aes")]
        let encrypted_method = encrypted_method || cfg!(feature = "gzip") && payload_method == 9;
        if encrypted && !encrypted_method {
            return Err(Self::error(
                ErrorKind::Unsupported,
                "forward-only encrypted ZIP compression method is not yet supported",
            ));
        }
        let zip64 = compressed32 == U32_SENTINEL || uncompressed32 == U32_SENTINEL;
        let sizes = if descriptor {
            None
        } else {
            Some(zip64_local_sizes(extra, compressed32, uncompressed32)?)
        };
        if let Some((compressed, uncompressed)) = sizes {
            if self
                .limits
                .entry_bytes()
                .is_some_and(|limit| uncompressed > limit)
            {
                return Err(Self::error(
                    ErrorKind::Limit,
                    "ZIP entry exceeds configured size limit",
                )
                .with_entry(self.entries, path.as_bytes()));
            }
            #[cfg(feature = "aes")]
            let aes_overhead = aes.map(|parameters| parameters.salt_len as u64 + 12);
            #[cfg(not(feature = "aes"))]
            let aes_overhead: Option<u64> = None;
            let stored_size_matches = if let Some(overhead) = aes_overhead {
                compressed.checked_sub(overhead) == Some(uncompressed)
            } else if encrypted {
                compressed.checked_sub(12) == Some(uncompressed)
            } else {
                compressed == uncompressed
            };
            if payload_method == 0 && !stored_size_matches {
                return Err(
                    Self::error(ErrorKind::Integrity, "stored ZIP entry sizes disagree")
                        .with_entry(self.entries, path.as_bytes()),
                );
            }
        }
        self.entries = self
            .entries
            .checked_add(1)
            .ok_or_else(|| Self::error(ErrorKind::Limit, "ZIP entry count overflow"))?;
        if self
            .limits
            .entries()
            .is_some_and(|limit| self.entries > limit)
        {
            return Err(Self::error(
                ErrorKind::Limit,
                "ZIP entry count exceeds configured limit",
            ));
        }
        self.account_metadata(
            name_length
                .checked_add(extra_length)
                .and_then(|value| value.checked_add(core::mem::size_of::<EntryMetadata>()))
                .ok_or_else(|| {
                    Self::error(ErrorKind::Limit, "ZIP entry metadata accounting overflow")
                })?,
        )?;

        let kind = if name.ends_with(b"/") {
            EntryKind::Dir
        } else {
            EntryKind::File
        };
        let mut builder = EntryMetadata::builder(kind, path)
            .size(sizes.map(|(_, uncompressed)| uncompressed))
            .owner(zip_unix_owner(extra)?)
            .times(zip_times(extra)?);
        let mut cursor = 0;
        while cursor < extra.len() {
            let id = le16(extra, cursor)?;
            let length = usize::from(le16(extra, cursor + 2)?);
            let start = cursor + 4;
            let finish = start + length;
            builder = builder.extension(Extension::new(
                "zip-extra",
                id.to_le_bytes().to_vec(),
                extra[start..finish].to_vec(),
            ));
            cursor = finish;
        }
        let metadata = builder.build();
        #[cfg(feature = "aes")]
        if let Some(parameters) = aes {
            let framing_len = parameters.salt_len.checked_add(2).ok_or_else(|| {
                Self::error(ErrorKind::Limit, "WinZip AES framing length overflow")
            })?;
            let encrypted_remaining = sizes
                .map(|(compressed, _)| {
                    compressed
                        .checked_sub(framing_len as u64 + 10)
                        .ok_or_else(|| {
                            Self::error(
                                ErrorKind::Malformed,
                                "WinZip AES payload is shorter than its framing",
                            )
                        })
                })
                .transpose()?;
            self.state = match payload_method {
                0 => State::AesStored(AesStored {
                    encrypted_remaining,
                    descriptor,
                    zip64,
                    buffer: Vec::with_capacity(if zip64 { 37 } else { 29 }),
                    framing: Vec::with_capacity(framing_len),
                    framing_len,
                    salt_len: parameters.salt_len,
                    strength: parameters.strength,
                    decoder: None,
                    produced: 0,
                    expected_size: sizes.map(|(_, uncompressed)| uncompressed),
                }),
                8 => State::AesDeflate(AesDeflate {
                    compressed_remaining: encrypted_remaining,
                    compressed: 0,
                    descriptor,
                    zip64,
                    framing: Vec::with_capacity(framing_len),
                    framing_len,
                    salt_len: parameters.salt_len,
                    strength: parameters.strength,
                    crypto: None,
                    decoder: RawInflateDecoder::with_limits(self.limits)?,
                    produced: 0,
                    expected_size: sizes.map(|(_, uncompressed)| uncompressed),
                }),
                #[cfg(feature = "gzip")]
                9 => State::AesDeflate64(AesDeflate64 {
                    compressed_remaining: encrypted_remaining,
                    compressed: 0,
                    loaded: 0,
                    descriptor,
                    zip64,
                    framing: Vec::with_capacity(framing_len),
                    framing_len,
                    salt_len: parameters.salt_len,
                    strength: parameters.strength,
                    crypto: None,
                    decoder: self.deflate64_decoder()?,
                    produced: 0,
                    expected_size: sizes.map(|(_, uncompressed)| uncompressed),
                }),
                #[cfg(any(feature = "bzip2", feature = "zstd", feature = "xz", feature = "ppmd"))]
                method => {
                    let (name, decoder, intrinsic) = match method {
                        #[cfg(feature = "bzip2")]
                        12 => (
                            "BZip2",
                            EncryptedPipelineDecoder::Bzip2(bzip2::Decompress::new(false)),
                            PipelineBoundary::Codec,
                        ),
                        #[cfg(feature = "xz")]
                        14 => (
                            "LZMA",
                            EncryptedPipelineDecoder::Lzma(EncryptedLzmaDecoder::new(
                                descriptor,
                                flags & 0x0002 != 0,
                                sizes.map(|(_, uncompressed)| uncompressed),
                                encrypted_remaining,
                            )?),
                            PipelineBoundary::Codec,
                        ),
                        #[cfg(feature = "ppmd")]
                        98 => (
                            "PPMd8",
                            EncryptedPipelineDecoder::Ppmd(EncryptedPpmdDecoder::new(
                                descriptor,
                                sizes.map(|(_, uncompressed)| uncompressed),
                                encrypted_remaining,
                            )?),
                            PipelineBoundary::Codec,
                        ),
                        #[cfg(feature = "zstd")]
                        93 => (
                            "Zstandard",
                            EncryptedPipelineDecoder::Codec(PipelineCodec::new(
                                FilterId::Zstd,
                                self.limits,
                            )?),
                            PipelineBoundary::Zstd(ZstdBoundary::new()),
                        ),
                        #[cfg(feature = "xz")]
                        95 => (
                            "XZ",
                            EncryptedPipelineDecoder::Codec(PipelineCodec::new(
                                FilterId::Xz,
                                self.limits,
                            )?),
                            PipelineBoundary::Xz(XzStreamBoundary::new(self.limits)),
                        ),
                        _ => {
                            return Err(Self::error(
                                ErrorKind::Unsupported,
                                "forward-only WinZip AES compression method is not yet supported",
                            ));
                        },
                    };
                    State::AesPipeline(AesPipeline {
                        name,
                        compressed_remaining: encrypted_remaining,
                        compressed: 0,
                        descriptor,
                        zip64,
                        framing: Vec::with_capacity(framing_len),
                        framing_len,
                        salt_len: parameters.salt_len,
                        strength: parameters.strength,
                        crypto: None,
                        decoder,
                        boundary: if descriptor {
                            intrinsic
                        } else {
                            PipelineBoundary::Known
                        },
                        produced: 0,
                        expected_size: sizes.map(|(_, uncompressed)| uncompressed),
                    })
                },
                #[cfg(not(any(
                    feature = "bzip2",
                    feature = "zstd",
                    feature = "xz",
                    feature = "ppmd"
                )))]
                _ => {
                    return Err(Self::error(
                        ErrorKind::Unsupported,
                        "forward-only WinZip AES compression method is not yet supported",
                    ));
                },
            };
            return Ok(DecodeStep {
                consumed,
                produced: 0,
                event: DecodeEvent::Entry(metadata),
            });
        }

        self.state = match (payload_method, descriptor, sizes, encrypted) {
            #[cfg(feature = "aes")]
            (0, false, Some((compressed, uncompressed)), true) => {
                State::ZipCryptoStored(ZipCryptoStored {
                    encrypted_remaining: Some(compressed.checked_sub(12).ok_or_else(|| {
                        Self::error(
                            ErrorKind::Malformed,
                            "ZipCrypto payload is shorter than its 12-byte header",
                        )
                    })?),
                    descriptor: false,
                    zip64,
                    buffer: Vec::new(),
                    header: [0; 12],
                    header_len: 0,
                    decoder: None,
                    verifier: (expected_crc >> 24) as u8,
                    expected_crc: Some(expected_crc),
                    crc: Crc32::new(),
                    produced: 0,
                    expected_size: Some(uncompressed),
                })
            },
            #[cfg(feature = "aes")]
            (0, true, _, true) => State::ZipCryptoStored(ZipCryptoStored {
                encrypted_remaining: None,
                descriptor: true,
                zip64,
                buffer: Vec::with_capacity(if zip64 { 27 } else { 19 }),
                header: [0; 12],
                header_len: 0,
                decoder: None,
                verifier: header[11],
                expected_crc: None,
                crc: Crc32::new(),
                produced: 0,
                expected_size: None,
            }),
            #[cfg(feature = "aes")]
            (8, descriptor, sizes, true) => State::ZipCryptoDeflate(ZipCryptoDeflate {
                compressed_remaining: sizes
                    .map(|(compressed, _)| {
                        compressed.checked_sub(12).ok_or_else(|| {
                            Self::error(
                                ErrorKind::Malformed,
                                "ZipCrypto payload is shorter than its 12-byte header",
                            )
                        })
                    })
                    .transpose()?,
                compressed: 0,
                descriptor,
                zip64,
                header: [0; 12],
                header_len: 0,
                crypto: None,
                verifier: if descriptor {
                    header[11]
                } else {
                    (expected_crc >> 24) as u8
                },
                decoder: RawInflateDecoder::with_limits(self.limits)?,
                expected_crc: (!descriptor).then_some(expected_crc),
                crc: Crc32::new(),
                produced: 0,
                expected_size: sizes.map(|(_, uncompressed)| uncompressed),
            }),
            #[cfg(all(feature = "aes", feature = "gzip"))]
            (9, descriptor, sizes, true) => State::ZipCryptoDeflate64(ZipCryptoDeflate64 {
                compressed_remaining: sizes
                    .map(|(compressed, _)| {
                        compressed.checked_sub(12).ok_or_else(|| {
                            Self::error(
                                ErrorKind::Malformed,
                                "ZipCrypto payload is shorter than its 12-byte header",
                            )
                        })
                    })
                    .transpose()?,
                compressed: 0,
                loaded: 0,
                descriptor,
                zip64,
                header: [0; 12],
                header_len: 0,
                crypto: None,
                verifier: if descriptor {
                    header[11]
                } else {
                    (expected_crc >> 24) as u8
                },
                decoder: self.deflate64_decoder()?,
                expected_crc: (!descriptor).then_some(expected_crc),
                crc: Crc32::new(),
                produced: 0,
                expected_size: sizes.map(|(_, uncompressed)| uncompressed),
            }),
            #[cfg(all(
                feature = "aes",
                any(feature = "bzip2", feature = "zstd", feature = "xz", feature = "ppmd")
            ))]
            (method, descriptor, sizes, true) => {
                let encrypted_remaining = sizes
                    .map(|(compressed, _)| {
                        compressed.checked_sub(12).ok_or_else(|| {
                            Self::error(
                                ErrorKind::Malformed,
                                "ZipCrypto payload is shorter than its 12-byte header",
                            )
                        })
                    })
                    .transpose()?;
                let (name, decoder, intrinsic) = match method {
                    #[cfg(feature = "bzip2")]
                    12 => (
                        "BZip2",
                        EncryptedPipelineDecoder::Bzip2(bzip2::Decompress::new(false)),
                        PipelineBoundary::Codec,
                    ),
                    #[cfg(feature = "xz")]
                    14 => (
                        "LZMA",
                        EncryptedPipelineDecoder::Lzma(EncryptedLzmaDecoder::new(
                            descriptor,
                            flags & 0x0002 != 0,
                            sizes.map(|(_, uncompressed)| uncompressed),
                            encrypted_remaining,
                        )?),
                        PipelineBoundary::Codec,
                    ),
                    #[cfg(feature = "ppmd")]
                    98 => (
                        "PPMd8",
                        EncryptedPipelineDecoder::Ppmd(EncryptedPpmdDecoder::new(
                            descriptor,
                            sizes.map(|(_, uncompressed)| uncompressed),
                            encrypted_remaining,
                        )?),
                        PipelineBoundary::Codec,
                    ),
                    #[cfg(feature = "zstd")]
                    93 => (
                        "Zstandard",
                        EncryptedPipelineDecoder::Codec(PipelineCodec::new(
                            FilterId::Zstd,
                            self.limits,
                        )?),
                        PipelineBoundary::Zstd(ZstdBoundary::new()),
                    ),
                    #[cfg(feature = "xz")]
                    95 => (
                        "XZ",
                        EncryptedPipelineDecoder::Codec(PipelineCodec::new(
                            FilterId::Xz,
                            self.limits,
                        )?),
                        PipelineBoundary::Xz(XzStreamBoundary::new(self.limits)),
                    ),
                    _ => {
                        return Err(Self::error(
                            ErrorKind::Protocol,
                            "encrypted ZIP pipeline method changed after validation",
                        ));
                    },
                };
                State::ZipCryptoPipeline(ZipCryptoPipeline {
                    name,
                    compressed_remaining: encrypted_remaining,
                    compressed: 0,
                    descriptor,
                    zip64,
                    header: [0; 12],
                    header_len: 0,
                    crypto: None,
                    verifier: if descriptor {
                        header[11]
                    } else {
                        (expected_crc >> 24) as u8
                    },
                    decoder,
                    boundary: if descriptor {
                        intrinsic
                    } else {
                        PipelineBoundary::Known
                    },
                    expected_crc: (!descriptor).then_some(expected_crc),
                    crc: Crc32::new(),
                    produced: 0,
                    expected_size: sizes.map(|(_, uncompressed)| uncompressed),
                })
            },
            (0, true, _, false) => State::StoredDescriptor(StoredDescriptor {
                buffer: Vec::with_capacity(if zip64 { 23 } else { 15 }),
                zip64,
                crc: Crc32::new(),
                produced: 0,
            }),
            (0, false, Some((compressed, uncompressed)), false) => {
                State::StoredKnown(StoredKnown {
                    remaining: compressed,
                    expected_crc,
                    crc: Crc32::new(),
                    produced: 0,
                    expected_size: uncompressed,
                })
            },
            (8, _, sizes, false) => State::Deflate(DeflateState {
                decoder: RawInflateDecoder::with_limits(self.limits)?,
                compressed_remaining: sizes.map(|(compressed, _)| compressed),
                compressed: 0,
                produced: 0,
                crc: Crc32::new(),
                expected_crc: (!descriptor).then_some(expected_crc),
                expected_size: sizes.map(|(_, uncompressed)| uncompressed),
                descriptor,
                zip64,
            }),
            #[cfg(feature = "gzip")]
            (9, descriptor, sizes, false) => State::Deflate64(Deflate64State {
                decoder: self.deflate64_decoder()?,
                compressed_remaining: sizes.map(|(compressed, _)| compressed),
                compressed: 0,
                loaded: 0,
                produced: 0,
                crc: Crc32::new(),
                expected_crc: (!descriptor).then_some(expected_crc),
                expected_size: sizes.map(|(_, uncompressed)| uncompressed),
                descriptor,
                zip64,
            }),
            #[cfg(feature = "xz")]
            (14, descriptor, sizes, false) => {
                let (compressed_remaining, expected_crc, expected_size) = if descriptor {
                    (None, None, None)
                } else {
                    let (compressed, uncompressed) = sizes.ok_or_else(|| {
                        Self::error(
                            ErrorKind::Malformed,
                            "known-size ZIP LZMA entry omitted its local sizes",
                        )
                    })?;
                    if compressed < 9 {
                        return Err(Self::error(
                            ErrorKind::Malformed,
                            "ZIP LZMA member is shorter than its 9-byte header",
                        ));
                    }
                    (Some(compressed), Some(expected_crc), Some(uncompressed))
                };
                State::Lzma(LzmaState {
                    decoder: None,
                    header: [0; 9],
                    header_len: 0,
                    compressed_remaining,
                    compressed: 0,
                    produced: 0,
                    crc: Crc32::new(),
                    expected_crc,
                    expected_size,
                    end_marker: flags & 0x0002 != 0,
                    descriptor,
                    zip64,
                })
            },
            #[cfg(feature = "zstd")]
            (93, _, sizes, false) => State::Pipeline(PipelineState {
                name: "Zstandard",
                decoder: PipelineCodec::new(FilterId::Zstd, self.limits)?,
                boundary: if descriptor {
                    PipelineBoundary::Zstd(ZstdBoundary::new())
                } else {
                    PipelineBoundary::Known
                },
                compressed_remaining: sizes.map(|pair| pair.0),
                compressed: 0,
                produced: 0,
                crc: Crc32::new(),
                expected_crc: (!descriptor).then_some(expected_crc),
                expected_size: sizes.map(|pair| pair.1),
                descriptor,
                zip64,
            }),
            #[cfg(feature = "xz")]
            (95, _, sizes, false) => State::Pipeline(PipelineState {
                name: "XZ",
                decoder: PipelineCodec::new(FilterId::Xz, self.limits)?,
                boundary: if descriptor {
                    PipelineBoundary::Xz(XzStreamBoundary::new(self.limits))
                } else {
                    PipelineBoundary::Known
                },
                compressed_remaining: sizes.map(|pair| pair.0),
                compressed: 0,
                produced: 0,
                crc: Crc32::new(),
                expected_crc: (!descriptor).then_some(expected_crc),
                expected_size: sizes.map(|pair| pair.1),
                descriptor,
                zip64,
            }),
            #[cfg(feature = "ppmd")]
            (98, descriptor, sizes, false) => {
                let (compressed_remaining, expected_crc, expected_size) = if descriptor {
                    (None, None, None)
                } else {
                    let (compressed, uncompressed) = sizes.ok_or_else(|| {
                        Self::error(
                            ErrorKind::Malformed,
                            "known-size ZIP PPMd entry omitted its local sizes",
                        )
                    })?;
                    if compressed < 6 {
                        return Err(Self::error(
                            ErrorKind::Malformed,
                            "ZIP PPMd member is shorter than its parameter and range headers",
                        ));
                    }
                    (Some(compressed), Some(expected_crc), Some(uncompressed))
                };
                State::Ppmd(PpmdState {
                    decoder: None,
                    header: [0; 2],
                    header_len: 0,
                    compressed_remaining,
                    compressed: 0,
                    produced: 0,
                    crc: Crc32::new(),
                    expected_crc,
                    expected_size,
                    descriptor,
                    zip64,
                })
            },
            #[cfg(feature = "bzip2")]
            (12, _, sizes, false) => State::Bzip2(Bzip2State {
                decoder: bzip2::Decompress::new(false),
                compressed_remaining: sizes.map(|(compressed, _)| compressed),
                compressed: 0,
                produced: 0,
                crc: Crc32::new(),
                expected_crc: (!descriptor).then_some(expected_crc),
                expected_size: sizes.map(|(_, uncompressed)| uncompressed),
                descriptor,
                zip64,
            }),
            _ => {
                return Err(Self::error(
                    ErrorKind::Protocol,
                    "ZIP entry body state could not be selected",
                ));
            },
        };
        Ok(DecodeStep {
            consumed,
            produced: 0,
            event: DecodeEvent::Entry(metadata),
        })
    }

    fn parse_eocd<'a>(
        &mut self,
        bytes: &[u8],
        consumed: usize,
    ) -> Result<DecodeStep<'a>, ArchiveError> {
        if le16(bytes, 4)? != 0 || le16(bytes, 6)? != 0 {
            return Err(Self::error(
                ErrorKind::Unsupported,
                "multi-disk ZIP requires a VolumeSet reader",
            ));
        }
        let on_disk = le16(bytes, 8)?;
        let total = le16(bytes, 10)?;
        let declared = if on_disk == U16_SENTINEL || total == U16_SENTINEL {
            self.zip64_entries.ok_or_else(|| {
                Self::error(
                    ErrorKind::Malformed,
                    "ZIP64 entry count sentinel has no ZIP64 end record",
                )
            })?
        } else {
            if on_disk != total {
                return Err(Self::error(
                    ErrorKind::Malformed,
                    "single-disk ZIP entry counts disagree",
                ));
            }
            u64::from(total)
        };
        if declared != self.entries || self.central_entries != self.entries {
            return Err(Self::error(
                ErrorKind::Integrity,
                "ZIP local and central-directory entry counts disagree",
            ));
        }
        let comment = bytes
            .get(22..)
            .ok_or_else(|| Self::error(ErrorKind::Malformed, "truncated ZIP archive comment"))?;
        self.account_metadata(comment.len())?;
        let metadata = if comment.is_empty() {
            ArchiveMetadata::new()
        } else {
            ArchiveMetadata::new().with_comment(comment.to_vec())
        };
        self.state = State::Done;
        Ok(DecodeStep {
            consumed,
            produced: 0,
            event: DecodeEvent::ArchiveMetadata(metadata),
        })
    }

    fn step_stored_known<'a>(
        &mut self,
        mut stored: StoredKnown,
        input: &'a [u8],
        end: EndOfInput,
    ) -> Result<DecodeStep<'a>, ArchiveError> {
        if stored.remaining == 0 {
            if stored.produced != stored.expected_size
                || stored.crc.finalize() != stored.expected_crc
            {
                return Err(Self::error(
                    ErrorKind::Integrity,
                    "stored ZIP entry size or CRC32 mismatch",
                ));
            }
            return Ok(self.finish_entry(0));
        }
        if input.is_empty() {
            if matches!(end, EndOfInput::End) {
                return Err(Self::error(
                    ErrorKind::Malformed,
                    "truncated stored ZIP payload",
                ));
            }
            self.state = State::StoredKnown(stored);
            return Ok(Self::need_input(0));
        }
        let count = usize::try_from(stored.remaining.min(input.len() as u64)).map_err(|_| {
            Self::error(ErrorKind::Limit, "ZIP stored extent exceeds address space")
        })?;
        let data = &input[..count];
        stored.crc.update(data);
        stored.remaining -= count as u64;
        stored.produced = stored
            .produced
            .checked_add(count as u64)
            .ok_or_else(|| Self::error(ErrorKind::Limit, "ZIP stored output count overflow"))?;
        self.account_entry_and_total(stored.produced, count)?;
        self.state = State::StoredKnown(stored);
        Ok(DecodeStep {
            consumed: count,
            produced: 0,
            event: DecodeEvent::Data(Chunk::new(data)),
        })
    }

    fn account_entry_and_total(
        &mut self,
        entry_total: u64,
        amount: usize,
    ) -> Result<(), ArchiveError> {
        if self
            .limits
            .entry_bytes()
            .is_some_and(|limit| entry_total > limit)
        {
            return Err(Self::error(
                ErrorKind::Limit,
                "ZIP entry exceeds configured size limit",
            ));
        }
        self.account_data(amount)
    }

    #[cfg(feature = "aes")]
    fn select_zipcrypto_decoder(
        &self,
        encrypted_header: [u8; 12],
        verifier: u8,
    ) -> Result<ZipCrypto, ArchiveError> {
        use subtle::ConstantTimeEq;

        if self.passwords.is_empty() {
            return Err(Self::error(
                ErrorKind::Unsupported,
                "ZipCrypto entry requires a password",
            ));
        }
        for password in &self.passwords {
            let mut decoder = ZipCrypto::new(password.expose());
            let mut header = encrypted_header;
            decoder.decrypt(&mut header);
            if header[11].ct_eq(&verifier).unwrap_u8() == 1 {
                return Ok(decoder);
            }
        }
        Err(Self::error(
            ErrorKind::Integrity,
            "no password candidate matched ZipCrypto verifier",
        ))
    }

    #[cfg(feature = "aes")]
    fn select_zip_aes_decoder(
        &self,
        salt: &[u8],
        verifier: [u8; 2],
        strength: u8,
    ) -> Result<ZipAesDecoder, ArchiveError> {
        if self.passwords.is_empty() {
            return Err(Self::error(
                ErrorKind::Unsupported,
                "WinZip AES entry requires a password",
            ));
        }
        let mut mismatch = None;
        for password in &self.passwords {
            match ZipAesDecoder::new(password.expose(), salt, verifier, strength) {
                Ok(decoder) => return Ok(decoder),
                Err(error) if error.kind() == ErrorKind::Integrity => mismatch = Some(error),
                Err(error) => return Err(error),
            }
        }
        Err(mismatch.unwrap_or_else(|| {
            Self::error(
                ErrorKind::Integrity,
                "no password candidate matched WinZip AES verifier",
            )
        }))
    }

    #[cfg(feature = "aes")]
    fn step_aes_stored<'a>(
        &mut self,
        mut stored: AesStored,
        input: &'a [u8],
        output: &'a mut [u8],
        end: EndOfInput,
    ) -> Result<DecodeStep<'a>, ArchiveError> {
        if stored.decoder.is_none() {
            let count = (stored.framing_len - stored.framing.len()).min(input.len());
            stored.framing.extend_from_slice(&input[..count]);
            if stored.framing.len() != stored.framing_len {
                if matches!(end, EndOfInput::End) && count == input.len() {
                    return Err(Self::error(
                        ErrorKind::Malformed,
                        "truncated WinZip AES salt or password verifier",
                    ));
                }
                self.state = State::AesStored(stored);
                return Ok(Self::need_input(count));
            }
            let verifier = [
                stored.framing[stored.salt_len],
                stored.framing[stored.salt_len + 1],
            ];
            stored.decoder = Some(self.select_zip_aes_decoder(
                &stored.framing[..stored.salt_len],
                verifier,
                stored.strength,
            )?);
            self.state = State::AesStored(stored);
            return Ok(Self::need_input(count));
        }
        if stored.descriptor {
            return self.step_aes_stored_descriptor(stored, input, output, end);
        }
        let remaining = stored.encrypted_remaining.ok_or_else(|| {
            Self::error(
                ErrorKind::Protocol,
                "known-size WinZip AES Store state lost its extent",
            )
        })?;
        if remaining == 0 {
            self.state = State::AesAuthentication(AesAuthentication {
                decoder: stored.decoder.take().ok_or_else(|| {
                    Self::error(
                        ErrorKind::Protocol,
                        "WinZip AES Store decoder disappeared before authentication",
                    )
                })?,
                bytes: Vec::with_capacity(10),
                produced: stored.produced,
                next: AesAuthenticationNext::EndEntry {
                    expected_size: stored.expected_size.ok_or_else(|| {
                        Self::error(
                            ErrorKind::Protocol,
                            "WinZip AES Store expected size disappeared",
                        )
                    })?,
                },
            });
            return Ok(Self::need_input(0));
        }
        if input.is_empty() {
            if matches!(end, EndOfInput::End) {
                return Err(Self::error(
                    ErrorKind::Malformed,
                    "truncated WinZip AES stored payload",
                ));
            }
            self.state = State::AesStored(stored);
            return Ok(Self::need_input(0));
        }
        if output.is_empty() {
            self.state = State::AesStored(stored);
            return Ok(DecodeStep {
                consumed: 0,
                produced: 0,
                event: DecodeEvent::NeedOutput,
            });
        }
        let count = usize::try_from(remaining.min(input.len() as u64).min(output.len() as u64))
            .map_err(|_| {
                Self::error(ErrorKind::Limit, "WinZip AES extent exceeds address space")
            })?;
        output[..count].copy_from_slice(&input[..count]);
        stored
            .decoder
            .as_mut()
            .ok_or_else(|| {
                Self::error(ErrorKind::Protocol, "WinZip AES Store decoder disappeared")
            })?
            .decrypt(&mut output[..count]);
        stored.encrypted_remaining = Some(remaining - count as u64);
        stored.produced = stored
            .produced
            .checked_add(count as u64)
            .ok_or_else(|| Self::error(ErrorKind::Limit, "WinZip AES output count overflow"))?;
        self.account_entry_and_total(stored.produced, count)?;
        self.state = State::AesStored(stored);
        Ok(DecodeStep {
            consumed: count,
            produced: count,
            event: DecodeEvent::Data(Chunk::new(&output[..count])),
        })
    }

    #[cfg(feature = "aes")]
    fn step_aes_authentication<'a>(
        &mut self,
        mut state: AesAuthentication,
        input: &'a [u8],
        end: EndOfInput,
    ) -> Result<DecodeStep<'a>, ArchiveError> {
        let count = (10 - state.bytes.len()).min(input.len());
        state.bytes.extend_from_slice(&input[..count]);
        if state.bytes.len() != 10 {
            if matches!(end, EndOfInput::End) && count == input.len() {
                return Err(Self::error(
                    ErrorKind::Malformed,
                    "truncated WinZip AES authentication code",
                ));
            }
            self.state = State::AesAuthentication(state);
            return Ok(Self::need_input(count));
        }
        let authentication: [u8; 10] = state.bytes.as_slice().try_into().map_err(|_| {
            Self::error(
                ErrorKind::Protocol,
                "WinZip AES authentication length changed after validation",
            )
        })?;
        state.decoder.verify(authentication)?;
        match state.next {
            AesAuthenticationNext::EndEntry { expected_size } => {
                if state.produced != expected_size {
                    return Err(Self::error(
                        ErrorKind::Integrity,
                        "WinZip AES size does not match the local header",
                    ));
                }
                Ok(self.finish_entry(count))
            },
            AesAuthenticationNext::Descriptor { zip64, compressed } => {
                self.state = State::Descriptor(DescriptorState {
                    bytes: Vec::new(),
                    zip64,
                    crc: 0,
                    compressed,
                    uncompressed: state.produced,
                });
                Ok(Self::need_input(count))
            },
        }
    }

    #[cfg(feature = "aes")]
    fn step_aes_stored_descriptor<'a>(
        &mut self,
        stored: AesStored,
        input: &'a [u8],
        output: &'a mut [u8],
        end: EndOfInput,
    ) -> Result<DecodeStep<'a>, ArchiveError> {
        let descriptor_len = if stored.zip64 { 24 } else { 16 };
        let retention = 10 + descriptor_len + 3;
        if self
            .limits
            .in_flight_bytes()
            .is_some_and(|limit| limit <= retention)
        {
            return Err(Self::error(
                ErrorKind::Limit,
                "ZIP in-flight limit is smaller than a WinZip AES data descriptor",
            ));
        }
        let maximum = self
            .limits
            .in_flight_bytes()
            .unwrap_or(usize::MAX)
            .saturating_sub(stored.buffer.len());
        let inspect = input.len().min(maximum);
        let mut combined = Vec::new();
        combined
            .try_reserve(stored.buffer.len().saturating_add(inspect))
            .map_err(|_| {
                Self::error(
                    ErrorKind::Limit,
                    "WinZip AES descriptor buffer allocation failed",
                )
            })?;
        combined.extend_from_slice(&stored.buffer);
        combined.extend_from_slice(&input[..inspect]);

        if let Some(index) = Self::valid_aes_stored_descriptor(&stored, &combined)? {
            if index > output.len() {
                return self
                    .emit_aes_descriptor_prefix(stored, combined, inspect, output, retention);
            }
            output[..index].copy_from_slice(&combined[..index]);
            let mut stored = stored;
            stored
                .decoder
                .as_mut()
                .ok_or_else(|| {
                    Self::error(
                        ErrorKind::Protocol,
                        "WinZip AES descriptor state has no decoder",
                    )
                })?
                .decrypt(&mut output[..index]);
            stored.produced = stored
                .produced
                .checked_add(index as u64)
                .ok_or_else(|| Self::error(ErrorKind::Limit, "WinZip AES output count overflow"))?;
            self.account_entry_and_total(stored.produced, index)?;
            let descriptor_end = index + 10 + descriptor_len;
            let consumed = descriptor_end.saturating_sub(stored.buffer.len());
            if index == 0 {
                return Ok(self.finish_entry(consumed));
            }
            self.state = State::EndEntry;
            return Ok(DecodeStep {
                consumed,
                produced: index,
                event: DecodeEvent::Data(Chunk::new(&output[..index])),
            });
        }
        if matches!(end, EndOfInput::End) && inspect == input.len() {
            return Err(Self::error(
                ErrorKind::Malformed,
                "WinZip AES stored data descriptor is missing or truncated",
            ));
        }
        self.emit_aes_descriptor_prefix(stored, combined, inspect, output, retention)
    }

    #[cfg(feature = "aes")]
    fn valid_aes_stored_descriptor(
        stored: &AesStored,
        bytes: &[u8],
    ) -> Result<Option<usize>, ArchiveError> {
        let descriptor_len = if stored.zip64 { 24 } else { 16 };
        let candidate_len = 10 + descriptor_len;
        if bytes.len() < candidate_len {
            return Ok(None);
        }
        for index in 0..=bytes.len() - candidate_len {
            let descriptor = index + 10;
            if bytes[descriptor..descriptor + 4] != DESCRIPTOR_SIGNATURE.to_le_bytes() {
                continue;
            }
            let crc = le32(bytes, descriptor + 4)?;
            let (compressed, uncompressed) = if stored.zip64 {
                (le64(bytes, descriptor + 8)?, le64(bytes, descriptor + 16)?)
            } else {
                (
                    u64::from(le32(bytes, descriptor + 8)?),
                    u64::from(le32(bytes, descriptor + 12)?),
                )
            };
            let candidate_produced =
                stored.produced.checked_add(index as u64).ok_or_else(|| {
                    Self::error(ErrorKind::Limit, "WinZip AES descriptor size overflow")
                })?;
            let framing = u64::try_from(stored.framing_len + 10).map_err(|_| {
                Self::error(
                    ErrorKind::Limit,
                    "WinZip AES framing length exceeds address space",
                )
            })?;
            if crc != 0
                || compressed != candidate_produced.saturating_add(framing)
                || uncompressed != candidate_produced
            {
                continue;
            }
            let authentication: [u8; 10] = bytes[index..descriptor].try_into().map_err(|_| {
                Self::error(
                    ErrorKind::Protocol,
                    "WinZip AES authentication candidate length changed",
                )
            })?;
            let decoder = stored.decoder.as_ref().ok_or_else(|| {
                Self::error(
                    ErrorKind::Protocol,
                    "WinZip AES descriptor validation has no decoder",
                )
            })?;
            if decoder
                .verify_after(&bytes[..index], authentication)
                .is_ok()
            {
                return Ok(Some(index));
            }
            if bytes
                .get(descriptor + descriptor_len..descriptor + descriptor_len + 4)
                .and_then(|next| next.try_into().ok())
                .map(u32::from_le_bytes)
                .is_some_and(|signature| {
                    matches!(
                        signature,
                        LOCAL_SIGNATURE | CENTRAL_SIGNATURE | EOCD_SIGNATURE | ZIP64_EOCD_SIGNATURE
                    )
                })
            {
                return Err(Self::error(
                    ErrorKind::Integrity,
                    "WinZip AES stored entry authentication failed",
                ));
            }
        }
        Ok(None)
    }

    #[cfg(feature = "aes")]
    fn emit_aes_descriptor_prefix<'a>(
        &mut self,
        mut stored: AesStored,
        combined: Vec<u8>,
        inspected_input: usize,
        output: &'a mut [u8],
        retention: usize,
    ) -> Result<DecodeStep<'a>, ArchiveError> {
        let safe = combined.len().saturating_sub(retention);
        if safe == 0 {
            stored.buffer = combined;
            self.state = State::AesStored(stored);
            return Ok(Self::need_input(inspected_input));
        }
        if output.is_empty() {
            self.state = State::AesStored(stored);
            return Ok(DecodeStep {
                consumed: 0,
                produced: 0,
                event: DecodeEvent::NeedOutput,
            });
        }
        let emitted = safe.min(output.len());
        let used = (emitted + retention).min(combined.len());
        output[..emitted].copy_from_slice(&combined[..emitted]);
        stored
            .decoder
            .as_mut()
            .ok_or_else(|| {
                Self::error(
                    ErrorKind::Protocol,
                    "WinZip AES descriptor state has no decoder",
                )
            })?
            .decrypt(&mut output[..emitted]);
        stored.produced = stored
            .produced
            .checked_add(emitted as u64)
            .ok_or_else(|| Self::error(ErrorKind::Limit, "WinZip AES output count overflow"))?;
        self.account_entry_and_total(stored.produced, emitted)?;
        stored.buffer.clear();
        stored.buffer.extend_from_slice(&combined[emitted..used]);
        let old_buffer = combined.len().saturating_sub(inspected_input);
        let consumed = used.saturating_sub(old_buffer);
        self.state = State::AesStored(stored);
        Ok(DecodeStep {
            consumed,
            produced: emitted,
            event: DecodeEvent::Data(Chunk::new(&output[..emitted])),
        })
    }

    #[cfg(feature = "aes")]
    #[allow(clippy::too_many_lines)]
    fn step_aes_deflate<'a>(
        &mut self,
        mut state: AesDeflate,
        input: &'a [u8],
        output: &'a mut [u8],
        end: EndOfInput,
    ) -> Result<DecodeStep<'a>, ArchiveError> {
        if state.crypto.is_none() {
            let count = (state.framing_len - state.framing.len()).min(input.len());
            state.framing.extend_from_slice(&input[..count]);
            if state.framing.len() != state.framing_len {
                if matches!(end, EndOfInput::End) && count == input.len() {
                    return Err(Self::error(
                        ErrorKind::Malformed,
                        "truncated WinZip AES salt or password verifier",
                    ));
                }
                self.state = State::AesDeflate(state);
                return Ok(Self::need_input(count));
            }
            let verifier = [
                state.framing[state.salt_len],
                state.framing[state.salt_len + 1],
            ];
            state.crypto = Some(self.select_zip_aes_decoder(
                &state.framing[..state.salt_len],
                verifier,
                state.strength,
            )?);
            self.state = State::AesDeflate(state);
            return Ok(Self::need_input(count));
        }
        if output.is_empty() {
            self.state = State::AesDeflate(state);
            return Ok(DecodeStep {
                consumed: 0,
                produced: 0,
                event: DecodeEvent::NeedOutput,
            });
        }
        let available = match state.compressed_remaining {
            Some(remaining) => {
                usize::try_from(remaining.min(input.len() as u64)).map_err(|_| {
                    Self::error(
                        ErrorKind::Limit,
                        "WinZip AES Deflate extent exceeds address space",
                    )
                })?
            },
            None => input.len(),
        };
        if available == 0 && state.compressed_remaining != Some(0) {
            if matches!(end, EndOfInput::End) {
                return Err(Self::error(
                    ErrorKind::Malformed,
                    "truncated WinZip AES Deflate payload",
                ));
            }
            self.state = State::AesDeflate(state);
            return Ok(Self::need_input(0));
        }
        let mut encoded = Vec::new();
        encoded.try_reserve_exact(available).map_err(|_| {
            Self::error(
                ErrorKind::Limit,
                "WinZip AES Deflate preview allocation failed",
            )
        })?;
        encoded.extend_from_slice(&input[..available]);
        state
            .crypto
            .as_ref()
            .ok_or_else(|| {
                Self::error(
                    ErrorKind::Protocol,
                    "WinZip AES Deflate state has no cipher",
                )
            })?
            .clone()
            .decrypt(&mut encoded);
        let codec_end = if state.compressed_remaining == Some(available as u64) {
            EndOfInput::End
        } else {
            EndOfInput::More
        };
        let codec = state
            .decoder
            .process_prefix(&encoded, output, codec_end)
            .map_err(|error| {
                if matches!(error.kind(), ErrorKind::Malformed | ErrorKind::Integrity) {
                    Self::error(
                        ErrorKind::Integrity,
                        "WinZip AES password or Deflate payload failed validation",
                    )
                } else {
                    error
                }
            })?
            .validate(encoded.len(), output.len())?;
        advance_aes(
            state.crypto.as_mut().ok_or_else(|| {
                Self::error(ErrorKind::Protocol, "WinZip AES Deflate cipher disappeared")
            })?,
            &input[..codec.consumed],
        );
        state.compressed = state
            .compressed
            .checked_add(codec.consumed as u64)
            .ok_or_else(|| Self::error(ErrorKind::Limit, "ZIP compressed count overflow"))?;
        if let Some(remaining) = &mut state.compressed_remaining {
            *remaining = remaining
                .checked_sub(codec.consumed as u64)
                .ok_or_else(|| {
                    Self::error(
                        ErrorKind::Protocol,
                        "WinZip AES Deflate decoder over-consumed its extent",
                    )
                })?;
        }
        state.produced = state
            .produced
            .checked_add(codec.produced as u64)
            .ok_or_else(|| Self::error(ErrorKind::Limit, "ZIP Deflate output count overflow"))?;
        self.account_entry_and_total(state.produced, codec.produced)?;

        if codec.status == CodecStatus::Done {
            if state
                .compressed_remaining
                .is_some_and(|remaining| remaining != 0)
            {
                return Err(Self::error(
                    ErrorKind::Integrity,
                    "WinZip AES Deflate stream ended before its declared extent",
                ));
            }
            let framing = u64::try_from(state.framing_len + 10).map_err(|_| {
                Self::error(ErrorKind::Limit, "WinZip AES framing exceeds address space")
            })?;
            let next = if state.descriptor {
                AesAuthenticationNext::Descriptor {
                    zip64: state.zip64,
                    compressed: state.compressed.checked_add(framing).ok_or_else(|| {
                        Self::error(ErrorKind::Limit, "WinZip AES compressed count overflow")
                    })?,
                }
            } else {
                AesAuthenticationNext::EndEntry {
                    expected_size: state.expected_size.ok_or_else(|| {
                        Self::error(
                            ErrorKind::Protocol,
                            "WinZip AES Deflate expected size disappeared",
                        )
                    })?,
                }
            };
            self.state = State::AesAuthentication(AesAuthentication {
                decoder: state.crypto.take().ok_or_else(|| {
                    Self::error(
                        ErrorKind::Protocol,
                        "WinZip AES Deflate cipher disappeared before authentication",
                    )
                })?,
                bytes: Vec::with_capacity(10),
                produced: state.produced,
                next,
            });
        } else {
            if !matches!(
                codec.status,
                CodecStatus::NeedInput | CodecStatus::NeedOutput
            ) {
                return Err(Self::error(
                    ErrorKind::Protocol,
                    "WinZip AES Deflate decoder returned an unknown status",
                ));
            }
            if codec.consumed == 0 && codec.produced == 0 && matches!(end, EndOfInput::End) {
                return Err(Self::error(
                    ErrorKind::Malformed,
                    "truncated WinZip AES Deflate stream",
                ));
            }
            self.state = State::AesDeflate(state);
        }
        if codec.produced != 0 {
            return Ok(DecodeStep {
                consumed: codec.consumed,
                produced: codec.produced,
                event: DecodeEvent::Data(Chunk::new(&output[..codec.produced])),
            });
        }
        Ok(Self::need_input(codec.consumed))
    }

    #[cfg(all(feature = "aes", feature = "gzip"))]
    #[allow(clippy::too_many_lines)]
    fn step_aes_deflate64<'a>(
        &mut self,
        mut state: AesDeflate64,
        input: &'a [u8],
        output: &'a mut [u8],
        end: EndOfInput,
    ) -> Result<DecodeStep<'a>, ArchiveError> {
        if state.crypto.is_none() {
            let count = (state.framing_len - state.framing.len()).min(input.len());
            state.framing.extend_from_slice(&input[..count]);
            if state.framing.len() != state.framing_len {
                if matches!(end, EndOfInput::End) && count == input.len() {
                    return Err(Self::error(
                        ErrorKind::Malformed,
                        "truncated WinZip AES salt or password verifier",
                    ));
                }
                self.state = State::AesDeflate64(state);
                return Ok(Self::need_input(count));
            }
            let verifier = [
                state.framing[state.salt_len],
                state.framing[state.salt_len + 1],
            ];
            state.crypto = Some(self.select_zip_aes_decoder(
                &state.framing[..state.salt_len],
                verifier,
                state.strength,
            )?);
            self.state = State::AesDeflate64(state);
            return Ok(Self::need_input(count));
        }
        if output.is_empty() {
            self.state = State::AesDeflate64(state);
            return Ok(DecodeStep {
                consumed: 0,
                produced: 0,
                event: DecodeEvent::NeedOutput,
            });
        }
        let prefetched = if state.descriptor {
            usize::try_from(state.loaded.checked_sub(state.compressed).ok_or_else(|| {
                Self::error(
                    ErrorKind::Protocol,
                    "WinZip AES Deflate64 committed input exceeds loaded input",
                )
            })?)
            .map_err(|_| {
                Self::error(
                    ErrorKind::Limit,
                    "WinZip AES Deflate64 look-ahead exceeds address space",
                )
            })?
        } else {
            0
        };
        if prefetched > input.len() {
            return Err(Self::error(
                ErrorKind::Protocol,
                "WinZip AES Deflate64 look-ahead is missing from pipeline input",
            ));
        }
        if state.compressed_remaining != Some(0) && input.is_empty() {
            if matches!(end, EndOfInput::End) {
                return Err(Self::error(
                    ErrorKind::Malformed,
                    "truncated WinZip AES Deflate64 payload",
                ));
            }
            self.state = State::AesDeflate64(state);
            return Ok(Self::need_input(0));
        }
        let available = match state.compressed_remaining {
            Some(remaining) => {
                usize::try_from(remaining.min(input.len() as u64)).map_err(|_| {
                    Self::error(
                        ErrorKind::Limit,
                        "WinZip AES Deflate64 extent exceeds address space",
                    )
                })?
            },
            None => input.len(),
        };
        let mut encoded = Vec::new();
        encoded.try_reserve_exact(available).map_err(|_| {
            Self::error(
                ErrorKind::Limit,
                "WinZip AES Deflate64 preview allocation failed",
            )
        })?;
        encoded.extend_from_slice(&input[..available]);
        state
            .crypto
            .as_ref()
            .ok_or_else(|| {
                Self::error(
                    ErrorKind::Protocol,
                    "WinZip AES Deflate64 state has no cipher",
                )
            })?
            .clone()
            .decrypt(&mut encoded);
        let result = match state.compressed_remaining {
            Some(remaining) => inflate64_extent_step(
                &mut state.decoder,
                &encoded,
                remaining - available as u64,
                output,
            ),
            None => state.decoder.inflate(&encoded[prefetched..], output),
        };
        if result.data_error || state.decoder.errored() {
            return Err(Self::error(
                ErrorKind::Integrity,
                "WinZip AES password or Deflate64 payload failed validation",
            ));
        }
        state.loaded = state
            .loaded
            .checked_add(result.bytes_consumed as u64)
            .ok_or_else(|| Self::error(ErrorKind::Limit, "ZIP loaded input count overflow"))?;
        let consumed = if state.descriptor {
            Self::deflate64_descriptor_consumed(&state.decoder, state.compressed, state.loaded)?
        } else {
            result.bytes_consumed
        };
        advance_aes(
            state.crypto.as_mut().ok_or_else(|| {
                Self::error(
                    ErrorKind::Protocol,
                    "WinZip AES Deflate64 cipher disappeared",
                )
            })?,
            &input[..consumed],
        );
        state.compressed = state
            .compressed
            .checked_add(consumed as u64)
            .ok_or_else(|| Self::error(ErrorKind::Limit, "ZIP compressed count overflow"))?;
        if !state.descriptor && state.loaded != state.compressed {
            return Err(Self::error(
                ErrorKind::Protocol,
                "known-size WinZip AES Deflate64 input accounting diverged",
            ));
        }
        if let Some(remaining) = &mut state.compressed_remaining {
            *remaining = remaining.checked_sub(consumed as u64).ok_or_else(|| {
                Self::error(
                    ErrorKind::Protocol,
                    "WinZip AES Deflate64 decoder over-consumed its extent",
                )
            })?;
        }
        state.produced = state
            .produced
            .checked_add(result.bytes_written as u64)
            .ok_or_else(|| {
                Self::error(
                    ErrorKind::Limit,
                    "WinZip AES Deflate64 output count overflow",
                )
            })?;
        self.account_entry_and_total(state.produced, result.bytes_written)?;

        if state.decoder.finished() {
            if state
                .compressed_remaining
                .is_some_and(|remaining| remaining != 0)
            {
                return Err(Self::error(
                    ErrorKind::Integrity,
                    "WinZip AES Deflate64 stream ended before its declared extent",
                ));
            }
            let framing = u64::try_from(state.framing_len + 10).map_err(|_| {
                Self::error(ErrorKind::Limit, "WinZip AES framing exceeds address space")
            })?;
            let next = if state.descriptor {
                AesAuthenticationNext::Descriptor {
                    zip64: state.zip64,
                    compressed: state.compressed.checked_add(framing).ok_or_else(|| {
                        Self::error(ErrorKind::Limit, "WinZip AES compressed count overflow")
                    })?,
                }
            } else {
                AesAuthenticationNext::EndEntry {
                    expected_size: state.expected_size.ok_or_else(|| {
                        Self::error(
                            ErrorKind::Protocol,
                            "WinZip AES Deflate64 expected size disappeared",
                        )
                    })?,
                }
            };
            self.state = State::AesAuthentication(AesAuthentication {
                decoder: state.crypto.take().ok_or_else(|| {
                    Self::error(
                        ErrorKind::Protocol,
                        "WinZip AES Deflate64 cipher disappeared before authentication",
                    )
                })?,
                bytes: Vec::with_capacity(10),
                produced: state.produced,
                next,
            });
        } else {
            if result.bytes_consumed == 0
                && result.bytes_written == 0
                && (state.compressed_remaining == Some(0) || matches!(end, EndOfInput::End))
            {
                return Err(Self::error(
                    ErrorKind::Malformed,
                    "truncated WinZip AES Deflate64 stream",
                ));
            }
            self.state = State::AesDeflate64(state);
        }
        if result.bytes_written != 0 {
            return Ok(DecodeStep {
                consumed,
                produced: result.bytes_written,
                event: DecodeEvent::Data(Chunk::new(&output[..result.bytes_written])),
            });
        }
        Ok(Self::need_input(consumed))
    }

    #[cfg(all(
        feature = "aes",
        any(feature = "bzip2", feature = "zstd", feature = "xz", feature = "ppmd")
    ))]
    #[allow(clippy::too_many_lines)]
    fn step_aes_pipeline<'a>(
        &mut self,
        mut state: AesPipeline,
        input: &'a [u8],
        output: &'a mut [u8],
        end: EndOfInput,
    ) -> Result<DecodeStep<'a>, ArchiveError> {
        if state.crypto.is_none() {
            let count = (state.framing_len - state.framing.len()).min(input.len());
            state.framing.extend_from_slice(&input[..count]);
            if state.framing.len() != state.framing_len {
                if matches!(end, EndOfInput::End) && count == input.len() {
                    return Err(Self::error(
                        ErrorKind::Malformed,
                        "truncated WinZip AES salt or password verifier",
                    ));
                }
                self.state = State::AesPipeline(state);
                return Ok(Self::need_input(count));
            }
            let verifier = [
                state.framing[state.salt_len],
                state.framing[state.salt_len + 1],
            ];
            state.crypto = Some(self.select_zip_aes_decoder(
                &state.framing[..state.salt_len],
                verifier,
                state.strength,
            )?);
            self.state = State::AesPipeline(state);
            return Ok(Self::need_input(count));
        }
        if output.is_empty() {
            self.state = State::AesPipeline(state);
            return Ok(DecodeStep {
                consumed: 0,
                produced: 0,
                event: DecodeEvent::NeedOutput,
            });
        }
        let encrypted_available = match state.compressed_remaining {
            Some(remaining) => {
                usize::try_from(remaining.min(input.len() as u64)).map_err(|_| {
                    Self::error(
                        ErrorKind::Limit,
                        format!("WinZip AES {} extent exceeds address space", state.name),
                    )
                })?
            },
            None => input.len(),
        };
        if encrypted_available == 0 && state.compressed_remaining != Some(0) {
            if matches!(end, EndOfInput::End) {
                return Err(Self::error(
                    ErrorKind::Malformed,
                    format!("truncated WinZip AES {} payload", state.name),
                ));
            }
            self.state = State::AesPipeline(state);
            return Ok(Self::need_input(0));
        }
        let mut encoded = Vec::new();
        encoded
            .try_reserve_exact(encrypted_available)
            .map_err(|_| {
                Self::error(
                    ErrorKind::Limit,
                    format!("WinZip AES {} preview allocation failed", state.name),
                )
            })?;
        encoded.extend_from_slice(&input[..encrypted_available]);
        state
            .crypto
            .as_ref()
            .ok_or_else(|| {
                Self::error(
                    ErrorKind::Protocol,
                    "WinZip AES pipeline state has no cipher",
                )
            })?
            .clone()
            .decrypt(&mut encoded);

        let (available, codec_end) = if state.compressed_remaining.is_some() {
            (
                encoded.len(),
                if state.compressed_remaining == Some(encoded.len() as u64) {
                    EndOfInput::End
                } else {
                    EndOfInput::More
                },
            )
        } else {
            let (available, frame_complete) =
                state
                    .boundary
                    .preview_encrypted(&encoded)
                    .map_err(|error| {
                        if matches!(error.kind(), ErrorKind::Malformed | ErrorKind::Integrity) {
                            Self::error(
                                ErrorKind::Integrity,
                                format!(
                                    "WinZip AES password or {} structure failed validation",
                                    state.name
                                ),
                            )
                        } else {
                            error
                        }
                    })?;
            (
                available,
                if frame_complete {
                    EndOfInput::End
                } else {
                    EndOfInput::More
                },
            )
        };
        #[cfg(not(any(feature = "zstd", feature = "xz", feature = "ppmd")))]
        let _ = codec_end;
        if available == 0
            && state.compressed_remaining != Some(0)
            && !matches!(codec_end, EndOfInput::End)
        {
            if matches!(end, EndOfInput::End) {
                return Err(Self::error(
                    ErrorKind::Malformed,
                    format!("truncated WinZip AES {} frame", state.name),
                ));
            }
            self.state = State::AesPipeline(state);
            return Ok(Self::need_input(0));
        }
        let (consumed, produced, status) = match &mut state.decoder {
            #[cfg(feature = "bzip2")]
            EncryptedPipelineDecoder::Bzip2(decoder) => {
                let before_in = decoder.total_in();
                let before_out = decoder.total_out();
                let result = decoder
                    .decompress(&encoded[..available], output)
                    .map_err(|_| {
                        Self::error(
                            ErrorKind::Integrity,
                            "WinZip AES password or BZip2 payload failed validation",
                        )
                    })?;
                if result == bzip2::Status::MemNeeded {
                    return Err(Self::error(
                        ErrorKind::Limit,
                        "WinZip AES BZip2 decoder ran out of memory",
                    ));
                }
                let consumed = usize::try_from(decoder.total_in() - before_in).map_err(|_| {
                    Self::error(ErrorKind::Limit, "WinZip AES BZip2 consumed count overflow")
                })?;
                let produced = usize::try_from(decoder.total_out() - before_out).map_err(|_| {
                    Self::error(ErrorKind::Limit, "WinZip AES BZip2 output count overflow")
                })?;
                let status = if result == bzip2::Status::StreamEnd {
                    CodecStatus::Done
                } else if produced == output.len() {
                    CodecStatus::NeedOutput
                } else {
                    CodecStatus::NeedInput
                };
                (consumed, produced, status)
            },
            #[cfg(feature = "xz")]
            EncryptedPipelineDecoder::Lzma(decoder) => {
                let codec = decoder
                    .process(&encoded[..available], output, codec_end, self.limits)
                    .map_err(|error| {
                        if matches!(error.kind(), ErrorKind::Malformed | ErrorKind::Integrity) {
                            Self::error(
                                ErrorKind::Integrity,
                                "WinZip AES password or LZMA payload failed validation",
                            )
                        } else {
                            error
                        }
                    })?
                    .validate(available, output.len())?;
                (codec.consumed, codec.produced, codec.status)
            },
            #[cfg(feature = "ppmd")]
            EncryptedPipelineDecoder::Ppmd(decoder) => {
                let codec = decoder
                    .process(&encoded[..available], output, codec_end, self.limits)
                    .map_err(|error| {
                        if matches!(error.kind(), ErrorKind::Malformed | ErrorKind::Integrity) {
                            Self::error(
                                ErrorKind::Integrity,
                                "WinZip AES password or PPMd8 payload failed validation",
                            )
                        } else {
                            error
                        }
                    })?
                    .validate(available, output.len())?;
                (codec.consumed, codec.produced, codec.status)
            },
            #[cfg(any(feature = "zstd", feature = "xz"))]
            EncryptedPipelineDecoder::Codec(decoder) => {
                let codec = decoder
                    .process(&encoded[..available], output, codec_end)
                    .map_err(|error| {
                        if matches!(error.kind(), ErrorKind::Malformed | ErrorKind::Integrity) {
                            Self::error(
                                ErrorKind::Integrity,
                                format!(
                                    "WinZip AES password or {} payload failed validation",
                                    state.name
                                ),
                            )
                        } else {
                            error
                        }
                    })?
                    .validate(available, output.len())?;
                (codec.consumed, codec.produced, codec.status)
            },
        };
        advance_aes(
            state.crypto.as_mut().ok_or_else(|| {
                Self::error(
                    ErrorKind::Protocol,
                    "WinZip AES pipeline cipher disappeared",
                )
            })?,
            &input[..consumed],
        );
        if state.compressed_remaining.is_none() {
            let tracked = state
                .boundary
                .consume(&encoded[..consumed])
                .map_err(|error| {
                    if matches!(error.kind(), ErrorKind::Malformed | ErrorKind::Integrity) {
                        Self::error(
                            ErrorKind::Integrity,
                            format!(
                                "WinZip AES password or {} structure failed validation",
                                state.name
                            ),
                        )
                    } else {
                        error
                    }
                })?;
            if tracked != consumed {
                return Err(Self::error(
                    ErrorKind::Protocol,
                    format!(
                        "WinZip AES {} decoder crossed its structural boundary",
                        state.name
                    ),
                ));
            }
        }
        state.compressed = state
            .compressed
            .checked_add(consumed as u64)
            .ok_or_else(|| Self::error(ErrorKind::Limit, "ZIP compressed count overflow"))?;
        if let Some(remaining) = &mut state.compressed_remaining {
            *remaining = remaining.checked_sub(consumed as u64).ok_or_else(|| {
                Self::error(
                    ErrorKind::Protocol,
                    format!("WinZip AES {} decoder over-consumed its extent", state.name),
                )
            })?;
        }
        state.produced = state.produced.checked_add(produced as u64).ok_or_else(|| {
            Self::error(
                ErrorKind::Limit,
                format!("ZIP {} output count overflow", state.name),
            )
        })?;
        self.account_entry_and_total(state.produced, produced)?;

        if status == CodecStatus::Done {
            if state
                .compressed_remaining
                .is_some_and(|remaining| remaining != 0)
            {
                return Err(Self::error(
                    ErrorKind::Integrity,
                    format!(
                        "WinZip AES {} stream ended before its declared extent",
                        state.name
                    ),
                ));
            }
            if state.compressed_remaining.is_none()
                && state.boundary.requires_structural_end()
                && !state.boundary.done()
            {
                return Err(Self::error(
                    ErrorKind::Integrity,
                    format!(
                        "WinZip AES {} decoder ended before its structural boundary",
                        state.name
                    ),
                ));
            }
            #[cfg(feature = "xz")]
            if state.descriptor && matches!(&state.boundary, PipelineBoundary::Xz(_)) {
                self.state = State::AesXzPadding(AesXzPadding {
                    crypto: state.crypto.take().ok_or_else(|| {
                        Self::error(
                            ErrorKind::Protocol,
                            "WinZip AES XZ cipher disappeared before padding",
                        )
                    })?,
                    bytes: Vec::new(),
                    zip64: state.zip64,
                    framing_len: state.framing_len,
                    compressed: state.compressed,
                    produced: state.produced,
                });
                if produced != 0 {
                    return Ok(DecodeStep {
                        consumed,
                        produced,
                        event: DecodeEvent::Data(Chunk::new(&output[..produced])),
                    });
                }
                return Ok(Self::need_input(consumed));
            }
            let framing = u64::try_from(state.framing_len + 10).map_err(|_| {
                Self::error(ErrorKind::Limit, "WinZip AES framing exceeds address space")
            })?;
            let next = if state.descriptor {
                AesAuthenticationNext::Descriptor {
                    zip64: state.zip64,
                    compressed: state.compressed.checked_add(framing).ok_or_else(|| {
                        Self::error(ErrorKind::Limit, "WinZip AES compressed count overflow")
                    })?,
                }
            } else {
                AesAuthenticationNext::EndEntry {
                    expected_size: state.expected_size.ok_or_else(|| {
                        Self::error(
                            ErrorKind::Protocol,
                            "WinZip AES pipeline expected size disappeared",
                        )
                    })?,
                }
            };
            self.state = State::AesAuthentication(AesAuthentication {
                decoder: state.crypto.take().ok_or_else(|| {
                    Self::error(
                        ErrorKind::Protocol,
                        "WinZip AES pipeline cipher disappeared before authentication",
                    )
                })?,
                bytes: Vec::with_capacity(10),
                produced: state.produced,
                next,
            });
        } else {
            if !matches!(status, CodecStatus::NeedInput | CodecStatus::NeedOutput) {
                return Err(Self::error(
                    ErrorKind::Protocol,
                    "WinZip AES pipeline decoder returned an unknown status",
                ));
            }
            if consumed == 0 && produced == 0 && matches!(end, EndOfInput::End) {
                return Err(Self::error(
                    ErrorKind::Malformed,
                    format!("truncated WinZip AES {} stream", state.name),
                ));
            }
            self.state = State::AesPipeline(state);
        }
        if produced != 0 {
            return Ok(DecodeStep {
                consumed,
                produced,
                event: DecodeEvent::Data(Chunk::new(&output[..produced])),
            });
        }
        Ok(Self::need_input(consumed))
    }

    #[cfg(all(feature = "aes", feature = "xz"))]
    fn step_aes_xz_padding<'a>(
        &mut self,
        mut state: AesXzPadding,
        input: &'a [u8],
        end: EndOfInput,
    ) -> Result<DecodeStep<'a>, ArchiveError> {
        let descriptor_len = if state.zip64 { 24 } else { 16 };
        let old_len = state.bytes.len();
        let maximum = self
            .limits
            .in_flight_bytes()
            .unwrap_or(usize::MAX)
            .saturating_sub(old_len);
        if maximum == 0 && !input.is_empty() {
            return Err(Self::error(
                ErrorKind::Limit,
                "WinZip AES XZ padding exceeds the in-flight limit",
            ));
        }
        let inspect = input.len().min(maximum);
        state.bytes.try_reserve(inspect).map_err(|_| {
            Self::error(
                ErrorKind::Limit,
                "WinZip AES XZ padding buffer allocation failed",
            )
        })?;
        state.bytes.extend_from_slice(&input[..inspect]);

        if let Some(candidate_end) = Self::valid_aes_xz_descriptor(&state, descriptor_len)? {
            let consumed = candidate_end.saturating_sub(old_len);
            return Ok(self.finish_entry(consumed));
        }
        if matches!(end, EndOfInput::End) && inspect == input.len() {
            return Err(Self::error(
                ErrorKind::Malformed,
                "WinZip AES XZ authentication or data descriptor is missing",
            ));
        }
        if inspect != input.len() {
            return Err(Self::error(
                ErrorKind::Limit,
                "WinZip AES XZ padding exceeds the in-flight limit",
            ));
        }
        self.state = State::AesXzPadding(state);
        Ok(Self::need_input(inspect))
    }

    #[cfg(all(feature = "aes", feature = "xz"))]
    fn valid_aes_xz_descriptor(
        state: &AesXzPadding,
        descriptor_len: usize,
    ) -> Result<Option<usize>, ArchiveError> {
        if state.bytes.len() < 10 + descriptor_len {
            return Ok(None);
        }
        for descriptor in 10..=state.bytes.len() - descriptor_len {
            if state.bytes[descriptor..descriptor + 4] != DESCRIPTOR_SIGNATURE.to_le_bytes() {
                continue;
            }
            let padding_len = descriptor - 10;
            if padding_len % 4 != 0 {
                continue;
            }
            let crc = le32(&state.bytes, descriptor + 4)?;
            let (compressed, uncompressed) = if state.zip64 {
                (
                    le64(&state.bytes, descriptor + 8)?,
                    le64(&state.bytes, descriptor + 16)?,
                )
            } else {
                (
                    u64::from(le32(&state.bytes, descriptor + 8)?),
                    u64::from(le32(&state.bytes, descriptor + 12)?),
                )
            };
            let framing = u64::try_from(state.framing_len + 10).map_err(|_| {
                Self::error(ErrorKind::Limit, "WinZip AES framing exceeds address space")
            })?;
            let expected_compressed = state
                .compressed
                .checked_add(padding_len as u64)
                .and_then(|value| value.checked_add(framing))
                .ok_or_else(|| {
                    Self::error(ErrorKind::Limit, "WinZip AES compressed count overflow")
                })?;
            if crc != 0 || compressed != expected_compressed || uncompressed != state.produced {
                continue;
            }
            let authentication: [u8; 10] = state.bytes[padding_len..descriptor]
                .try_into()
                .map_err(|_| {
                    Self::error(
                        ErrorKind::Protocol,
                        "WinZip AES XZ authentication candidate length changed",
                    )
                })?;
            let mut preview = state.crypto.clone();
            let mut padding = state.bytes[..padding_len].to_vec();
            preview.decrypt(&mut padding);
            if padding.iter().all(|byte| *byte == 0) && preview.verify(authentication).is_ok() {
                return Ok(Some(descriptor + descriptor_len));
            }
            if state
                .bytes
                .get(descriptor + descriptor_len..descriptor + descriptor_len + 4)
                .and_then(|next| next.try_into().ok())
                .map(u32::from_le_bytes)
                .is_some_and(|signature| {
                    matches!(
                        signature,
                        LOCAL_SIGNATURE | CENTRAL_SIGNATURE | EOCD_SIGNATURE | ZIP64_EOCD_SIGNATURE
                    )
                })
            {
                return Err(Self::error(
                    ErrorKind::Integrity,
                    "WinZip AES XZ padding or authentication failed",
                ));
            }
        }
        Ok(None)
    }

    #[cfg(feature = "aes")]
    fn step_zipcrypto_stored<'a>(
        &mut self,
        mut stored: ZipCryptoStored,
        input: &'a [u8],
        output: &'a mut [u8],
        end: EndOfInput,
    ) -> Result<DecodeStep<'a>, ArchiveError> {
        if stored.decoder.is_none() {
            let count = (stored.header.len() - stored.header_len).min(input.len());
            stored.header[stored.header_len..stored.header_len + count]
                .copy_from_slice(&input[..count]);
            stored.header_len += count;
            if stored.header_len != stored.header.len() {
                if matches!(end, EndOfInput::End) && count == input.len() {
                    return Err(Self::error(
                        ErrorKind::Malformed,
                        "truncated ZipCrypto encryption header",
                    ));
                }
                self.state = State::ZipCryptoStored(stored);
                return Ok(Self::need_input(count));
            }
            stored.decoder = Some(self.select_zipcrypto_decoder(stored.header, stored.verifier)?);
            self.state = State::ZipCryptoStored(stored);
            return Ok(Self::need_input(count));
        }

        if stored.descriptor {
            return self.step_zipcrypto_stored_descriptor(stored, input, output, end);
        }
        let remaining = stored.encrypted_remaining.ok_or_else(|| {
            Self::error(
                ErrorKind::Protocol,
                "known-size ZipCrypto entry lost its encrypted extent",
            )
        })?;
        if remaining == 0 {
            if Some(stored.produced) != stored.expected_size
                || Some(stored.crc.finalize()) != stored.expected_crc
            {
                return Err(Self::error(
                    ErrorKind::Integrity,
                    "ZipCrypto stored size or CRC32 mismatch",
                ));
            }
            return Ok(self.finish_entry(0));
        }
        if input.is_empty() {
            if matches!(end, EndOfInput::End) {
                return Err(Self::error(
                    ErrorKind::Malformed,
                    "truncated ZipCrypto stored payload",
                ));
            }
            self.state = State::ZipCryptoStored(stored);
            return Ok(Self::need_input(0));
        }
        if output.is_empty() {
            self.state = State::ZipCryptoStored(stored);
            return Ok(DecodeStep {
                consumed: 0,
                produced: 0,
                event: DecodeEvent::NeedOutput,
            });
        }
        let count = usize::try_from(remaining.min(input.len() as u64).min(output.len() as u64))
            .map_err(|_| Self::error(ErrorKind::Limit, "ZipCrypto extent exceeds address space"))?;
        output[..count].copy_from_slice(&input[..count]);
        stored
            .decoder
            .as_mut()
            .ok_or_else(|| {
                Self::error(
                    ErrorKind::Protocol,
                    "ZipCrypto decoder disappeared after header validation",
                )
            })?
            .decrypt(&mut output[..count]);
        stored.crc.update(&output[..count]);
        stored.encrypted_remaining = Some(remaining - count as u64);
        stored.produced = stored
            .produced
            .checked_add(count as u64)
            .ok_or_else(|| Self::error(ErrorKind::Limit, "ZipCrypto output count overflow"))?;
        self.account_entry_and_total(stored.produced, count)?;
        if stored.encrypted_remaining == Some(0) {
            if Some(stored.produced) != stored.expected_size
                || Some(stored.crc.finalize()) != stored.expected_crc
            {
                return Err(Self::error(
                    ErrorKind::Integrity,
                    "ZipCrypto stored size or CRC32 mismatch",
                ));
            }
            self.state = State::EndEntry;
        } else {
            self.state = State::ZipCryptoStored(stored);
        }
        Ok(DecodeStep {
            consumed: count,
            produced: count,
            event: DecodeEvent::Data(Chunk::new(&output[..count])),
        })
    }

    #[cfg(feature = "aes")]
    fn step_zipcrypto_stored_descriptor<'a>(
        &mut self,
        stored: ZipCryptoStored,
        input: &'a [u8],
        output: &'a mut [u8],
        end: EndOfInput,
    ) -> Result<DecodeStep<'a>, ArchiveError> {
        let descriptor_len = if stored.zip64 { 24 } else { 16 };
        let retention = descriptor_len + 3;
        if self
            .limits
            .in_flight_bytes()
            .is_some_and(|limit| limit <= retention)
        {
            return Err(Self::error(
                ErrorKind::Limit,
                "ZIP in-flight limit is smaller than a ZipCrypto data descriptor",
            ));
        }
        let maximum = self
            .limits
            .in_flight_bytes()
            .unwrap_or(usize::MAX)
            .saturating_sub(stored.buffer.len());
        let inspect = input.len().min(maximum);
        let mut combined = Vec::new();
        combined
            .try_reserve(stored.buffer.len().saturating_add(inspect))
            .map_err(|_| {
                Self::error(
                    ErrorKind::Limit,
                    "ZipCrypto descriptor buffer allocation failed",
                )
            })?;
        combined.extend_from_slice(&stored.buffer);
        combined.extend_from_slice(&input[..inspect]);

        if let Some(index) = Self::valid_zipcrypto_stored_descriptor(&stored, &combined)? {
            if index > output.len() {
                return self.emit_zipcrypto_descriptor_prefix(
                    stored, combined, inspect, output, retention,
                );
            }
            output[..index].copy_from_slice(&combined[..index]);
            let mut stored = stored;
            stored
                .decoder
                .as_mut()
                .ok_or_else(|| {
                    Self::error(
                        ErrorKind::Protocol,
                        "ZipCrypto descriptor state has no decoder",
                    )
                })?
                .decrypt(&mut output[..index]);
            stored.crc.update(&output[..index]);
            let produced = stored
                .produced
                .checked_add(index as u64)
                .ok_or_else(|| Self::error(ErrorKind::Limit, "ZipCrypto output count overflow"))?;
            self.account_entry_and_total(produced, index)?;
            let descriptor_end = index + descriptor_len;
            let consumed = descriptor_end.saturating_sub(stored.buffer.len());
            if index == 0 {
                return Ok(self.finish_entry(consumed));
            }
            self.state = State::EndEntry;
            return Ok(DecodeStep {
                consumed,
                produced: index,
                event: DecodeEvent::Data(Chunk::new(&output[..index])),
            });
        }

        if matches!(end, EndOfInput::End) && inspect == input.len() {
            return Err(Self::error(
                ErrorKind::Malformed,
                "ZipCrypto stored data descriptor is missing or truncated",
            ));
        }
        self.emit_zipcrypto_descriptor_prefix(stored, combined, inspect, output, retention)
    }

    #[cfg(feature = "aes")]
    fn valid_zipcrypto_stored_descriptor(
        stored: &ZipCryptoStored,
        bytes: &[u8],
    ) -> Result<Option<usize>, ArchiveError> {
        let descriptor_len = if stored.zip64 { 24 } else { 16 };
        if bytes.len() < descriptor_len {
            return Ok(None);
        }
        for index in 0..=bytes.len() - descriptor_len {
            if bytes[index..index + 4] != DESCRIPTOR_SIGNATURE.to_le_bytes() {
                continue;
            }
            let crc = le32(bytes, index + 4)?;
            let (compressed, uncompressed) = if stored.zip64 {
                (le64(bytes, index + 8)?, le64(bytes, index + 16)?)
            } else {
                (
                    u64::from(le32(bytes, index + 8)?),
                    u64::from(le32(bytes, index + 12)?),
                )
            };
            let candidate_produced =
                stored.produced.checked_add(index as u64).ok_or_else(|| {
                    Self::error(ErrorKind::Limit, "ZipCrypto descriptor size overflow")
                })?;
            if compressed != candidate_produced.saturating_add(12)
                || uncompressed != candidate_produced
            {
                continue;
            }
            let mut decoder = stored
                .decoder
                .as_ref()
                .ok_or_else(|| {
                    Self::error(
                        ErrorKind::Protocol,
                        "ZipCrypto descriptor validation has no decoder",
                    )
                })?
                .clone();
            let mut candidate_crc = stored.crc;
            let mut position = 0;
            let mut scratch = [0_u8; 1024];
            while position < index {
                let count = (index - position).min(scratch.len());
                scratch[..count].copy_from_slice(&bytes[position..position + count]);
                decoder.decrypt(&mut scratch[..count]);
                candidate_crc.update(&scratch[..count]);
                position += count;
            }
            if candidate_crc.finalize() == crc {
                return Ok(Some(index));
            }
            if bytes
                .get(index + descriptor_len..index + descriptor_len + 4)
                .and_then(|next| next.try_into().ok())
                .map(u32::from_le_bytes)
                .is_some_and(|signature| {
                    matches!(
                        signature,
                        LOCAL_SIGNATURE | CENTRAL_SIGNATURE | EOCD_SIGNATURE | ZIP64_EOCD_SIGNATURE
                    )
                })
            {
                return Err(Self::error(
                    ErrorKind::Integrity,
                    "ZipCrypto stored entry CRC32 does not match its data descriptor",
                ));
            }
        }
        Ok(None)
    }

    #[cfg(feature = "aes")]
    fn emit_zipcrypto_descriptor_prefix<'a>(
        &mut self,
        mut stored: ZipCryptoStored,
        combined: Vec<u8>,
        inspected_input: usize,
        output: &'a mut [u8],
        retention: usize,
    ) -> Result<DecodeStep<'a>, ArchiveError> {
        let safe = combined.len().saturating_sub(retention);
        if safe == 0 {
            stored.buffer = combined;
            self.state = State::ZipCryptoStored(stored);
            return Ok(Self::need_input(inspected_input));
        }
        if output.is_empty() {
            self.state = State::ZipCryptoStored(stored);
            return Ok(DecodeStep {
                consumed: 0,
                produced: 0,
                event: DecodeEvent::NeedOutput,
            });
        }
        let emitted = safe.min(output.len());
        let used = (emitted + retention).min(combined.len());
        output[..emitted].copy_from_slice(&combined[..emitted]);
        stored
            .decoder
            .as_mut()
            .ok_or_else(|| {
                Self::error(
                    ErrorKind::Protocol,
                    "ZipCrypto descriptor state has no decoder",
                )
            })?
            .decrypt(&mut output[..emitted]);
        stored.crc.update(&output[..emitted]);
        stored.produced = stored
            .produced
            .checked_add(emitted as u64)
            .ok_or_else(|| Self::error(ErrorKind::Limit, "ZipCrypto output count overflow"))?;
        self.account_entry_and_total(stored.produced, emitted)?;
        stored.buffer.clear();
        stored.buffer.extend_from_slice(&combined[emitted..used]);
        let old_buffer = combined.len().saturating_sub(inspected_input);
        let consumed = used.saturating_sub(old_buffer);
        self.state = State::ZipCryptoStored(stored);
        Ok(DecodeStep {
            consumed,
            produced: emitted,
            event: DecodeEvent::Data(Chunk::new(&output[..emitted])),
        })
    }

    #[cfg(feature = "aes")]
    #[allow(clippy::too_many_lines)]
    fn step_zipcrypto_deflate<'a>(
        &mut self,
        mut state: ZipCryptoDeflate,
        input: &'a [u8],
        output: &'a mut [u8],
        end: EndOfInput,
    ) -> Result<DecodeStep<'a>, ArchiveError> {
        if state.crypto.is_none() {
            let count = (state.header.len() - state.header_len).min(input.len());
            state.header[state.header_len..state.header_len + count]
                .copy_from_slice(&input[..count]);
            state.header_len += count;
            if state.header_len != state.header.len() {
                if matches!(end, EndOfInput::End) && count == input.len() {
                    return Err(Self::error(
                        ErrorKind::Malformed,
                        "truncated ZipCrypto encryption header",
                    ));
                }
                self.state = State::ZipCryptoDeflate(state);
                return Ok(Self::need_input(count));
            }
            state.crypto = Some(self.select_zipcrypto_decoder(state.header, state.verifier)?);
            self.state = State::ZipCryptoDeflate(state);
            return Ok(Self::need_input(count));
        }
        if output.is_empty() {
            self.state = State::ZipCryptoDeflate(state);
            return Ok(DecodeStep {
                consumed: 0,
                produced: 0,
                event: DecodeEvent::NeedOutput,
            });
        }
        let available = match state.compressed_remaining {
            Some(remaining) => {
                usize::try_from(remaining.min(input.len() as u64)).map_err(|_| {
                    Self::error(
                        ErrorKind::Limit,
                        "ZipCrypto Deflate extent exceeds address space",
                    )
                })?
            },
            None => input.len(),
        };
        if available == 0 {
            if matches!(end, EndOfInput::End) {
                return Err(Self::error(
                    ErrorKind::Malformed,
                    "truncated ZipCrypto Deflate payload",
                ));
            }
            self.state = State::ZipCryptoDeflate(state);
            return Ok(Self::need_input(0));
        }
        let mut encoded = Vec::new();
        encoded.try_reserve_exact(available).map_err(|_| {
            Self::error(
                ErrorKind::Limit,
                "ZipCrypto Deflate preview allocation failed",
            )
        })?;
        encoded.extend_from_slice(&input[..available]);
        state
            .crypto
            .as_ref()
            .ok_or_else(|| {
                Self::error(
                    ErrorKind::Protocol,
                    "ZipCrypto Deflate state has no key stream",
                )
            })?
            .clone()
            .decrypt(&mut encoded);
        let codec_end = if state.compressed_remaining == Some(available as u64) {
            EndOfInput::End
        } else {
            EndOfInput::More
        };
        let codec = state
            .decoder
            .process_prefix(&encoded, output, codec_end)
            .map_err(|error| {
                if matches!(error.kind(), ErrorKind::Malformed | ErrorKind::Integrity) {
                    Self::error(
                        ErrorKind::Integrity,
                        "ZipCrypto password or Deflate payload failed validation",
                    )
                } else {
                    error
                }
            })?
            .validate(encoded.len(), output.len())?;
        advance_zipcrypto(
            state.crypto.as_mut().ok_or_else(|| {
                Self::error(
                    ErrorKind::Protocol,
                    "ZipCrypto Deflate key stream disappeared",
                )
            })?,
            &input[..codec.consumed],
        );
        state.compressed = state
            .compressed
            .checked_add(codec.consumed as u64)
            .ok_or_else(|| Self::error(ErrorKind::Limit, "ZIP compressed count overflow"))?;
        if let Some(remaining) = &mut state.compressed_remaining {
            *remaining = remaining
                .checked_sub(codec.consumed as u64)
                .ok_or_else(|| {
                    Self::error(
                        ErrorKind::Protocol,
                        "ZipCrypto Deflate decoder over-consumed its extent",
                    )
                })?;
        }
        state.produced = state
            .produced
            .checked_add(codec.produced as u64)
            .ok_or_else(|| Self::error(ErrorKind::Limit, "ZIP Deflate output count overflow"))?;
        state.crc.update(&output[..codec.produced]);
        self.account_entry_and_total(state.produced, codec.produced)?;

        if codec.status == CodecStatus::Done {
            if state
                .compressed_remaining
                .is_some_and(|remaining| remaining != 0)
            {
                return Err(Self::error(
                    ErrorKind::Integrity,
                    "ZipCrypto Deflate stream ended before its declared extent",
                ));
            }
            if state.descriptor {
                self.state = State::Descriptor(DescriptorState {
                    bytes: Vec::new(),
                    zip64: state.zip64,
                    crc: state.crc.finalize(),
                    compressed: state.compressed.checked_add(12).ok_or_else(|| {
                        Self::error(ErrorKind::Limit, "ZipCrypto compressed count overflow")
                    })?,
                    uncompressed: state.produced,
                });
            } else {
                if state.expected_size != Some(state.produced)
                    || state.expected_crc != Some(state.crc.finalize())
                {
                    return Err(Self::error(
                        ErrorKind::Integrity,
                        "ZipCrypto Deflate size or CRC32 mismatch",
                    ));
                }
                self.state = State::EndEntry;
            }
        } else {
            if !matches!(
                codec.status,
                CodecStatus::NeedInput | CodecStatus::NeedOutput
            ) {
                return Err(Self::error(
                    ErrorKind::Protocol,
                    "ZipCrypto Deflate decoder returned an unknown status",
                ));
            }
            if codec.consumed == 0 && codec.produced == 0 && matches!(end, EndOfInput::End) {
                return Err(Self::error(
                    ErrorKind::Malformed,
                    "truncated ZipCrypto Deflate stream",
                ));
            }
            self.state = State::ZipCryptoDeflate(state);
        }
        if codec.produced != 0 {
            return Ok(DecodeStep {
                consumed: codec.consumed,
                produced: codec.produced,
                event: DecodeEvent::Data(Chunk::new(&output[..codec.produced])),
            });
        }
        Ok(Self::need_input(codec.consumed))
    }

    #[cfg(all(feature = "aes", feature = "gzip"))]
    #[allow(clippy::too_many_lines)]
    fn step_zipcrypto_deflate64<'a>(
        &mut self,
        mut state: ZipCryptoDeflate64,
        input: &'a [u8],
        output: &'a mut [u8],
        end: EndOfInput,
    ) -> Result<DecodeStep<'a>, ArchiveError> {
        if state.crypto.is_none() {
            let count = (state.header.len() - state.header_len).min(input.len());
            state.header[state.header_len..state.header_len + count]
                .copy_from_slice(&input[..count]);
            state.header_len += count;
            if state.header_len != state.header.len() {
                if matches!(end, EndOfInput::End) && count == input.len() {
                    return Err(Self::error(
                        ErrorKind::Malformed,
                        "truncated ZipCrypto encryption header",
                    ));
                }
                self.state = State::ZipCryptoDeflate64(state);
                return Ok(Self::need_input(count));
            }
            state.crypto = Some(self.select_zipcrypto_decoder(state.header, state.verifier)?);
            self.state = State::ZipCryptoDeflate64(state);
            return Ok(Self::need_input(count));
        }
        if output.is_empty() {
            self.state = State::ZipCryptoDeflate64(state);
            return Ok(DecodeStep {
                consumed: 0,
                produced: 0,
                event: DecodeEvent::NeedOutput,
            });
        }
        let prefetched = if state.descriptor {
            usize::try_from(state.loaded.checked_sub(state.compressed).ok_or_else(|| {
                Self::error(
                    ErrorKind::Protocol,
                    "ZipCrypto Deflate64 committed input exceeds loaded input",
                )
            })?)
            .map_err(|_| {
                Self::error(
                    ErrorKind::Limit,
                    "ZipCrypto Deflate64 look-ahead exceeds address space",
                )
            })?
        } else {
            0
        };
        if prefetched > input.len() {
            return Err(Self::error(
                ErrorKind::Protocol,
                "ZipCrypto Deflate64 look-ahead is missing from pipeline input",
            ));
        }
        if state.compressed_remaining != Some(0) && input.is_empty() {
            if matches!(end, EndOfInput::End) {
                return Err(Self::error(
                    ErrorKind::Malformed,
                    "truncated ZipCrypto Deflate64 payload",
                ));
            }
            self.state = State::ZipCryptoDeflate64(state);
            return Ok(Self::need_input(0));
        }
        let available = match state.compressed_remaining {
            Some(remaining) => {
                usize::try_from(remaining.min(input.len() as u64)).map_err(|_| {
                    Self::error(
                        ErrorKind::Limit,
                        "ZipCrypto Deflate64 extent exceeds address space",
                    )
                })?
            },
            None => input.len(),
        };
        let mut encoded = Vec::new();
        encoded.try_reserve_exact(available).map_err(|_| {
            Self::error(
                ErrorKind::Limit,
                "ZipCrypto Deflate64 preview allocation failed",
            )
        })?;
        encoded.extend_from_slice(&input[..available]);
        state
            .crypto
            .as_ref()
            .ok_or_else(|| {
                Self::error(
                    ErrorKind::Protocol,
                    "ZipCrypto Deflate64 state has no key stream",
                )
            })?
            .clone()
            .decrypt(&mut encoded);
        let result = match state.compressed_remaining {
            Some(remaining) => inflate64_extent_step(
                &mut state.decoder,
                &encoded,
                remaining - available as u64,
                output,
            ),
            None => state.decoder.inflate(&encoded[prefetched..], output),
        };
        if result.data_error || state.decoder.errored() {
            return Err(Self::error(
                ErrorKind::Integrity,
                "ZipCrypto password or Deflate64 payload failed validation",
            ));
        }
        state.loaded = state
            .loaded
            .checked_add(result.bytes_consumed as u64)
            .ok_or_else(|| Self::error(ErrorKind::Limit, "ZIP loaded input count overflow"))?;
        let consumed = if state.descriptor {
            Self::deflate64_descriptor_consumed(&state.decoder, state.compressed, state.loaded)?
        } else {
            result.bytes_consumed
        };
        advance_zipcrypto(
            state.crypto.as_mut().ok_or_else(|| {
                Self::error(
                    ErrorKind::Protocol,
                    "ZipCrypto Deflate64 key stream disappeared",
                )
            })?,
            &input[..consumed],
        );
        state.compressed = state
            .compressed
            .checked_add(consumed as u64)
            .ok_or_else(|| Self::error(ErrorKind::Limit, "ZIP compressed count overflow"))?;
        if !state.descriptor && state.loaded != state.compressed {
            return Err(Self::error(
                ErrorKind::Protocol,
                "known-size ZipCrypto Deflate64 input accounting diverged",
            ));
        }
        if let Some(remaining) = &mut state.compressed_remaining {
            *remaining = remaining.checked_sub(consumed as u64).ok_or_else(|| {
                Self::error(
                    ErrorKind::Protocol,
                    "ZipCrypto Deflate64 decoder over-consumed its extent",
                )
            })?;
        }
        state.produced = state
            .produced
            .checked_add(result.bytes_written as u64)
            .ok_or_else(|| Self::error(ErrorKind::Limit, "ZIP Deflate64 output count overflow"))?;
        state.crc.update(&output[..result.bytes_written]);
        self.account_entry_and_total(state.produced, result.bytes_written)?;

        if state.decoder.finished() {
            if state
                .compressed_remaining
                .is_some_and(|remaining| remaining != 0)
            {
                return Err(Self::error(
                    ErrorKind::Integrity,
                    "ZipCrypto Deflate64 stream ended before its declared extent",
                ));
            }
            if state.descriptor {
                self.state = State::Descriptor(DescriptorState {
                    bytes: Vec::new(),
                    zip64: state.zip64,
                    crc: state.crc.finalize(),
                    compressed: state.compressed.checked_add(12).ok_or_else(|| {
                        Self::error(ErrorKind::Limit, "ZipCrypto compressed count overflow")
                    })?,
                    uncompressed: state.produced,
                });
            } else {
                if state.expected_size != Some(state.produced)
                    || state.expected_crc != Some(state.crc.finalize())
                {
                    return Err(Self::error(
                        ErrorKind::Integrity,
                        "ZipCrypto Deflate64 size or CRC32 mismatch",
                    ));
                }
                self.state = State::EndEntry;
            }
        } else {
            if result.bytes_consumed == 0
                && result.bytes_written == 0
                && (state.compressed_remaining == Some(0) || matches!(end, EndOfInput::End))
            {
                return Err(Self::error(
                    ErrorKind::Malformed,
                    "truncated ZipCrypto Deflate64 stream",
                ));
            }
            self.state = State::ZipCryptoDeflate64(state);
        }
        if result.bytes_written != 0 {
            return Ok(DecodeStep {
                consumed,
                produced: result.bytes_written,
                event: DecodeEvent::Data(Chunk::new(&output[..result.bytes_written])),
            });
        }
        Ok(Self::need_input(consumed))
    }

    #[cfg(all(
        feature = "aes",
        any(feature = "bzip2", feature = "zstd", feature = "xz", feature = "ppmd")
    ))]
    #[allow(clippy::too_many_lines)]
    fn step_zipcrypto_pipeline<'a>(
        &mut self,
        mut state: ZipCryptoPipeline,
        input: &'a [u8],
        output: &'a mut [u8],
        end: EndOfInput,
    ) -> Result<DecodeStep<'a>, ArchiveError> {
        if state.crypto.is_none() {
            let count = (state.header.len() - state.header_len).min(input.len());
            state.header[state.header_len..state.header_len + count]
                .copy_from_slice(&input[..count]);
            state.header_len += count;
            if state.header_len != state.header.len() {
                if matches!(end, EndOfInput::End) && count == input.len() {
                    return Err(Self::error(
                        ErrorKind::Malformed,
                        "truncated ZipCrypto encryption header",
                    ));
                }
                self.state = State::ZipCryptoPipeline(state);
                return Ok(Self::need_input(count));
            }
            state.crypto = Some(self.select_zipcrypto_decoder(state.header, state.verifier)?);
            self.state = State::ZipCryptoPipeline(state);
            return Ok(Self::need_input(count));
        }
        if output.is_empty() {
            self.state = State::ZipCryptoPipeline(state);
            return Ok(DecodeStep {
                consumed: 0,
                produced: 0,
                event: DecodeEvent::NeedOutput,
            });
        }
        let encrypted_available = match state.compressed_remaining {
            Some(remaining) => {
                usize::try_from(remaining.min(input.len() as u64)).map_err(|_| {
                    Self::error(
                        ErrorKind::Limit,
                        format!("ZipCrypto {} extent exceeds address space", state.name),
                    )
                })?
            },
            None => input.len(),
        };
        if encrypted_available == 0 && state.compressed_remaining != Some(0) {
            if matches!(end, EndOfInput::End) {
                return Err(Self::error(
                    ErrorKind::Malformed,
                    format!("truncated ZipCrypto {} payload", state.name),
                ));
            }
            self.state = State::ZipCryptoPipeline(state);
            return Ok(Self::need_input(0));
        }
        let mut encoded = Vec::new();
        encoded
            .try_reserve_exact(encrypted_available)
            .map_err(|_| {
                Self::error(
                    ErrorKind::Limit,
                    format!("ZipCrypto {} preview allocation failed", state.name),
                )
            })?;
        encoded.extend_from_slice(&input[..encrypted_available]);
        state
            .crypto
            .as_ref()
            .ok_or_else(|| {
                Self::error(
                    ErrorKind::Protocol,
                    "ZipCrypto pipeline state has no key stream",
                )
            })?
            .clone()
            .decrypt(&mut encoded);

        let (available, codec_end) = if state.compressed_remaining.is_some() {
            (
                encoded.len(),
                if state.compressed_remaining == Some(encoded.len() as u64) {
                    EndOfInput::End
                } else {
                    EndOfInput::More
                },
            )
        } else {
            let (available, frame_complete) =
                state
                    .boundary
                    .preview_encrypted(&encoded)
                    .map_err(|error| {
                        if matches!(error.kind(), ErrorKind::Malformed | ErrorKind::Integrity) {
                            Self::error(
                                ErrorKind::Integrity,
                                format!(
                                    "ZipCrypto password or {} structure failed validation",
                                    state.name
                                ),
                            )
                        } else {
                            error
                        }
                    })?;
            (
                available,
                if frame_complete {
                    EndOfInput::End
                } else {
                    EndOfInput::More
                },
            )
        };
        #[cfg(not(any(feature = "zstd", feature = "xz", feature = "ppmd")))]
        let _ = codec_end;
        if available == 0 && !matches!(codec_end, EndOfInput::End) {
            if matches!(end, EndOfInput::End) {
                return Err(Self::error(
                    ErrorKind::Malformed,
                    format!("truncated ZipCrypto {} frame", state.name),
                ));
            }
            self.state = State::ZipCryptoPipeline(state);
            return Ok(Self::need_input(0));
        }
        let (consumed, produced, status) = match &mut state.decoder {
            #[cfg(feature = "bzip2")]
            EncryptedPipelineDecoder::Bzip2(decoder) => {
                let before_in = decoder.total_in();
                let before_out = decoder.total_out();
                let result = decoder
                    .decompress(&encoded[..available], output)
                    .map_err(|_| {
                        Self::error(
                            ErrorKind::Integrity,
                            "ZipCrypto password or BZip2 payload failed validation",
                        )
                    })?;
                if result == bzip2::Status::MemNeeded {
                    return Err(Self::error(
                        ErrorKind::Limit,
                        "ZipCrypto BZip2 decoder ran out of memory",
                    ));
                }
                let consumed = usize::try_from(decoder.total_in() - before_in).map_err(|_| {
                    Self::error(ErrorKind::Limit, "ZipCrypto BZip2 consumed count overflow")
                })?;
                let produced = usize::try_from(decoder.total_out() - before_out).map_err(|_| {
                    Self::error(ErrorKind::Limit, "ZipCrypto BZip2 output count overflow")
                })?;
                let status = if result == bzip2::Status::StreamEnd {
                    CodecStatus::Done
                } else if produced == output.len() {
                    CodecStatus::NeedOutput
                } else {
                    CodecStatus::NeedInput
                };
                (consumed, produced, status)
            },
            #[cfg(feature = "xz")]
            EncryptedPipelineDecoder::Lzma(decoder) => {
                let codec = decoder
                    .process(&encoded[..available], output, codec_end, self.limits)
                    .map_err(|error| {
                        if matches!(error.kind(), ErrorKind::Malformed | ErrorKind::Integrity) {
                            Self::error(
                                ErrorKind::Integrity,
                                "ZipCrypto password or LZMA payload failed validation",
                            )
                        } else {
                            error
                        }
                    })?
                    .validate(available, output.len())?;
                (codec.consumed, codec.produced, codec.status)
            },
            #[cfg(feature = "ppmd")]
            EncryptedPipelineDecoder::Ppmd(decoder) => {
                let codec = decoder
                    .process(&encoded[..available], output, codec_end, self.limits)
                    .map_err(|error| {
                        if matches!(error.kind(), ErrorKind::Malformed | ErrorKind::Integrity) {
                            Self::error(
                                ErrorKind::Integrity,
                                "ZipCrypto password or PPMd8 payload failed validation",
                            )
                        } else {
                            error
                        }
                    })?
                    .validate(available, output.len())?;
                (codec.consumed, codec.produced, codec.status)
            },
            #[cfg(any(feature = "zstd", feature = "xz"))]
            EncryptedPipelineDecoder::Codec(decoder) => {
                let codec = decoder
                    .process(&encoded[..available], output, codec_end)
                    .map_err(|error| {
                        if matches!(error.kind(), ErrorKind::Malformed | ErrorKind::Integrity) {
                            Self::error(
                                ErrorKind::Integrity,
                                format!(
                                    "ZipCrypto password or {} payload failed validation",
                                    state.name
                                ),
                            )
                        } else {
                            error
                        }
                    })?
                    .validate(available, output.len())?;
                (codec.consumed, codec.produced, codec.status)
            },
        };
        advance_zipcrypto(
            state.crypto.as_mut().ok_or_else(|| {
                Self::error(
                    ErrorKind::Protocol,
                    "ZipCrypto pipeline key stream disappeared",
                )
            })?,
            &input[..consumed],
        );
        if state.compressed_remaining.is_none() {
            let tracked = state
                .boundary
                .consume(&encoded[..consumed])
                .map_err(|error| {
                    if matches!(error.kind(), ErrorKind::Malformed | ErrorKind::Integrity) {
                        Self::error(
                            ErrorKind::Integrity,
                            format!(
                                "ZipCrypto password or {} structure failed validation",
                                state.name
                            ),
                        )
                    } else {
                        error
                    }
                })?;
            if tracked != consumed {
                return Err(Self::error(
                    ErrorKind::Protocol,
                    format!(
                        "ZipCrypto {} decoder crossed its structural boundary",
                        state.name
                    ),
                ));
            }
        }
        state.compressed = state
            .compressed
            .checked_add(consumed as u64)
            .ok_or_else(|| Self::error(ErrorKind::Limit, "ZIP compressed count overflow"))?;
        if let Some(remaining) = &mut state.compressed_remaining {
            *remaining = remaining.checked_sub(consumed as u64).ok_or_else(|| {
                Self::error(
                    ErrorKind::Protocol,
                    format!("ZipCrypto {} decoder over-consumed its extent", state.name),
                )
            })?;
        }
        state.produced = state.produced.checked_add(produced as u64).ok_or_else(|| {
            Self::error(
                ErrorKind::Limit,
                format!("ZIP {} output count overflow", state.name),
            )
        })?;
        state.crc.update(&output[..produced]);
        self.account_entry_and_total(state.produced, produced)?;

        if status == CodecStatus::Done {
            if state
                .compressed_remaining
                .is_some_and(|remaining| remaining != 0)
            {
                return Err(Self::error(
                    ErrorKind::Integrity,
                    format!(
                        "ZipCrypto {} stream ended before its declared extent",
                        state.name
                    ),
                ));
            }
            if state.compressed_remaining.is_none()
                && state.boundary.requires_structural_end()
                && !state.boundary.done()
            {
                return Err(Self::error(
                    ErrorKind::Integrity,
                    format!(
                        "ZipCrypto {} decoder ended before its structural boundary",
                        state.name
                    ),
                ));
            }
            if state.descriptor {
                let compressed = state.compressed.checked_add(12).ok_or_else(|| {
                    Self::error(ErrorKind::Limit, "ZipCrypto compressed count overflow")
                })?;
                #[cfg(feature = "xz")]
                if matches!(&state.boundary, PipelineBoundary::Xz(_)) {
                    self.state = State::ZipCryptoXzPadding(ZipCryptoXzPadding {
                        crypto: state.crypto.take().ok_or_else(|| {
                            Self::error(
                                ErrorKind::Protocol,
                                "ZipCrypto XZ key stream disappeared before padding",
                            )
                        })?,
                        bytes: Vec::with_capacity(4),
                        zip64: state.zip64,
                        crc: state.crc.finalize(),
                        compressed,
                        uncompressed: state.produced,
                    });
                } else {
                    self.state = State::Descriptor(DescriptorState {
                        bytes: Vec::new(),
                        zip64: state.zip64,
                        crc: state.crc.finalize(),
                        compressed,
                        uncompressed: state.produced,
                    });
                }
                #[cfg(not(feature = "xz"))]
                {
                    self.state = State::Descriptor(DescriptorState {
                        bytes: Vec::new(),
                        zip64: state.zip64,
                        crc: state.crc.finalize(),
                        compressed,
                        uncompressed: state.produced,
                    });
                }
            } else {
                if state.expected_size != Some(state.produced)
                    || state.expected_crc != Some(state.crc.finalize())
                {
                    return Err(Self::error(
                        ErrorKind::Integrity,
                        format!("ZipCrypto {} size or CRC32 mismatch", state.name),
                    ));
                }
                self.state = State::EndEntry;
            }
        } else {
            if !matches!(status, CodecStatus::NeedInput | CodecStatus::NeedOutput) {
                return Err(Self::error(
                    ErrorKind::Protocol,
                    format!(
                        "ZipCrypto {} decoder returned an unknown status",
                        state.name
                    ),
                ));
            }
            if consumed == 0 && produced == 0 && matches!(end, EndOfInput::End) {
                return Err(Self::error(
                    ErrorKind::Malformed,
                    format!("truncated ZipCrypto {} stream", state.name),
                ));
            }
            self.state = State::ZipCryptoPipeline(state);
        }
        if produced != 0 {
            return Ok(DecodeStep {
                consumed,
                produced,
                event: DecodeEvent::Data(Chunk::new(&output[..produced])),
            });
        }
        Ok(Self::need_input(consumed))
    }

    #[cfg(all(feature = "aes", feature = "xz"))]
    fn step_zipcrypto_xz_padding<'a>(
        &mut self,
        mut state: ZipCryptoXzPadding,
        input: &'a [u8],
        end: EndOfInput,
    ) -> Result<DecodeStep<'a>, ArchiveError> {
        let needed = 4_usize.saturating_sub(state.bytes.len());
        let count = needed.min(input.len());
        state.bytes.extend_from_slice(&input[..count]);
        if state.bytes.len() != 4 {
            if matches!(end, EndOfInput::End) && count == input.len() {
                return Err(Self::error(
                    ErrorKind::Malformed,
                    "truncated ZipCrypto XZ padding or data descriptor",
                ));
            }
            self.state = State::ZipCryptoXzPadding(state);
            return Ok(Self::need_input(count));
        }
        if state.bytes == DESCRIPTOR_SIGNATURE.to_le_bytes() {
            self.state = State::Descriptor(DescriptorState {
                bytes: core::mem::take(&mut state.bytes),
                zip64: state.zip64,
                crc: state.crc,
                compressed: state.compressed,
                uncompressed: state.uncompressed,
            });
            return Ok(Self::need_input(count));
        }
        state.crypto.decrypt(&mut state.bytes);
        if state.bytes != [0; 4] {
            return Err(Self::error(
                ErrorKind::Integrity,
                "ZipCrypto XZ padding is not an aligned zero group",
            ));
        }
        state.compressed = state.compressed.checked_add(4).ok_or_else(|| {
            Self::error(ErrorKind::Limit, "ZipCrypto XZ compressed count overflow")
        })?;
        state.bytes.clear();
        self.state = State::ZipCryptoXzPadding(state);
        Ok(Self::need_input(count))
    }

    fn step_stored_descriptor<'a>(
        &mut self,
        stored: StoredDescriptor,
        input: &'a [u8],
        output: &'a mut [u8],
        end: EndOfInput,
    ) -> Result<DecodeStep<'a>, ArchiveError> {
        let descriptor_len = if stored.zip64 { 24 } else { 16 };
        let retention = descriptor_len - 1;
        if self
            .limits
            .in_flight_bytes()
            .is_some_and(|limit| limit < descriptor_len)
        {
            return Err(Self::error(
                ErrorKind::Limit,
                "ZIP in-flight limit is smaller than a data descriptor",
            ));
        }
        let maximum = self
            .limits
            .in_flight_bytes()
            .unwrap_or(usize::MAX)
            .saturating_sub(stored.buffer.len());
        let inspect = input.len().min(maximum);
        let mut combined = Vec::new();
        combined
            .try_reserve(stored.buffer.len().saturating_add(inspect))
            .map_err(|_| {
                Self::error(ErrorKind::Limit, "ZIP descriptor buffer allocation failed")
            })?;
        combined.extend_from_slice(&stored.buffer);
        combined.extend_from_slice(&input[..inspect]);

        if let Some(index) = valid_stored_descriptor(&stored, &combined) {
            if index > output.len() {
                return self
                    .emit_stored_descriptor_prefix(stored, combined, inspect, output, retention);
            }
            output[..index].copy_from_slice(&combined[..index]);
            let mut crc = stored.crc;
            crc.update(&combined[..index]);
            let produced = stored
                .produced
                .checked_add(index as u64)
                .ok_or_else(|| Self::error(ErrorKind::Limit, "ZIP stored output count overflow"))?;
            self.account_entry_and_total(produced, index)?;
            let descriptor_end = index + descriptor_len;
            let consumed = descriptor_end.saturating_sub(stored.buffer.len());
            if index == 0 {
                return Ok(self.finish_entry(consumed));
            }
            self.state = State::EndEntry;
            return Ok(DecodeStep {
                consumed,
                produced: index,
                event: DecodeEvent::Data(Chunk::new(&output[..index])),
            });
        }

        if matches!(end, EndOfInput::End) && inspect == input.len() {
            return Err(Self::error(
                ErrorKind::Malformed,
                "stored ZIP data descriptor is missing or truncated",
            ));
        }
        self.emit_stored_descriptor_prefix(stored, combined, inspect, output, retention)
    }

    fn emit_stored_descriptor_prefix<'a>(
        &mut self,
        mut stored: StoredDescriptor,
        combined: Vec<u8>,
        inspected_input: usize,
        output: &'a mut [u8],
        retention: usize,
    ) -> Result<DecodeStep<'a>, ArchiveError> {
        let safe = combined.len().saturating_sub(retention);
        if safe == 0 {
            stored.buffer = combined;
            self.state = State::StoredDescriptor(stored);
            return Ok(Self::need_input(inspected_input));
        }
        if output.is_empty() {
            self.state = State::StoredDescriptor(stored);
            return Ok(DecodeStep {
                consumed: 0,
                produced: 0,
                event: DecodeEvent::NeedOutput,
            });
        }
        let emitted = safe.min(output.len());
        let used = (emitted + retention).min(combined.len());
        output[..emitted].copy_from_slice(&combined[..emitted]);
        stored.crc.update(&combined[..emitted]);
        stored.produced = stored
            .produced
            .checked_add(emitted as u64)
            .ok_or_else(|| Self::error(ErrorKind::Limit, "ZIP stored output count overflow"))?;
        self.account_entry_and_total(stored.produced, emitted)?;
        stored.buffer.clear();
        stored.buffer.extend_from_slice(&combined[emitted..used]);
        let old_buffer = combined.len().saturating_sub(inspected_input);
        let consumed = used.saturating_sub(old_buffer);
        self.state = State::StoredDescriptor(stored);
        Ok(DecodeStep {
            consumed,
            produced: emitted,
            event: DecodeEvent::Data(Chunk::new(&output[..emitted])),
        })
    }

    #[allow(clippy::too_many_lines)]
    fn step_deflate<'a>(
        &mut self,
        mut state: DeflateState,
        input: &'a [u8],
        output: &'a mut [u8],
        end: EndOfInput,
    ) -> Result<DecodeStep<'a>, ArchiveError> {
        if output.is_empty() {
            self.state = State::Deflate(state);
            return Ok(DecodeStep {
                consumed: 0,
                produced: 0,
                event: DecodeEvent::NeedOutput,
            });
        }
        let available = match state.compressed_remaining {
            Some(remaining) => {
                usize::try_from(remaining.min(input.len() as u64)).map_err(|_| {
                    Self::error(ErrorKind::Limit, "ZIP deflate extent exceeds address space")
                })?
            },
            None => input.len(),
        };
        if available == 0 {
            if matches!(end, EndOfInput::End) {
                return Err(Self::error(
                    ErrorKind::Malformed,
                    "truncated ZIP deflate payload",
                ));
            }
            self.state = State::Deflate(state);
            return Ok(Self::need_input(0));
        }
        let encoded = &input[..available];
        let codec_end = if state.compressed_remaining == Some(available as u64) {
            EndOfInput::End
        } else {
            EndOfInput::More
        };
        let codec = state
            .decoder
            .process_prefix(encoded, output, codec_end)?
            .validate(encoded.len(), output.len())?;
        state.compressed = state
            .compressed
            .checked_add(codec.consumed as u64)
            .ok_or_else(|| Self::error(ErrorKind::Limit, "ZIP compressed count overflow"))?;
        if let Some(remaining) = &mut state.compressed_remaining {
            *remaining = remaining
                .checked_sub(codec.consumed as u64)
                .ok_or_else(|| {
                    Self::error(
                        ErrorKind::Protocol,
                        "ZIP deflate decoder over-consumed its extent",
                    )
                })?;
        }
        state.produced = state
            .produced
            .checked_add(codec.produced as u64)
            .ok_or_else(|| Self::error(ErrorKind::Limit, "ZIP deflate output count overflow"))?;
        state.crc.update(&output[..codec.produced]);
        self.account_entry_and_total(state.produced, codec.produced)?;

        let done = codec.status == CodecStatus::Done;
        if done {
            if state
                .compressed_remaining
                .is_some_and(|remaining| remaining != 0)
            {
                return Err(Self::error(
                    ErrorKind::Integrity,
                    "ZIP deflate stream ended before its declared extent",
                ));
            }
            if state.descriptor {
                self.state = State::Descriptor(DescriptorState {
                    bytes: Vec::new(),
                    zip64: state.zip64,
                    crc: state.crc.finalize(),
                    compressed: state.compressed,
                    uncompressed: state.produced,
                });
            } else {
                if state.expected_size != Some(state.produced)
                    || state.expected_crc != Some(state.crc.finalize())
                {
                    return Err(Self::error(
                        ErrorKind::Integrity,
                        "ZIP deflate size or CRC32 mismatch",
                    ));
                }
                self.state = State::EndEntry;
            }
        } else {
            if !matches!(
                codec.status,
                CodecStatus::NeedInput | CodecStatus::NeedOutput
            ) {
                return Err(Self::error(
                    ErrorKind::Protocol,
                    "ZIP deflate decoder returned an unknown status",
                ));
            }
            if codec.consumed == 0 && codec.produced == 0 && matches!(end, EndOfInput::End) {
                return Err(Self::error(
                    ErrorKind::Malformed,
                    "truncated ZIP deflate stream",
                ));
            }
            self.state = State::Deflate(state);
        }
        if codec.produced != 0 {
            return Ok(DecodeStep {
                consumed: codec.consumed,
                produced: codec.produced,
                event: DecodeEvent::Data(Chunk::new(&output[..codec.produced])),
            });
        }
        Ok(Self::need_input(codec.consumed))
    }

    fn step_descriptor<'a>(
        &mut self,
        mut descriptor: DescriptorState,
        input: &'a [u8],
        end: EndOfInput,
    ) -> Result<DecodeStep<'a>, ArchiveError> {
        let unsigned = if descriptor.zip64 { 20 } else { 12 };
        let signed = unsigned + 4;
        let initial = 4_usize.saturating_sub(descriptor.bytes.len());
        let first = initial.min(input.len());
        descriptor.bytes.extend_from_slice(&input[..first]);
        let mut consumed = first;
        if descriptor.bytes.len() < 4 {
            if matches!(end, EndOfInput::End) && consumed == input.len() {
                return Err(Self::error(
                    ErrorKind::Malformed,
                    "truncated ZIP data descriptor",
                ));
            }
            self.state = State::Descriptor(descriptor);
            return Ok(Self::need_input(consumed));
        }
        let target = if le32(&descriptor.bytes, 0)? == DESCRIPTOR_SIGNATURE {
            signed
        } else {
            unsigned
        };
        let needed = target - descriptor.bytes.len();
        let count = needed.min(input.len().saturating_sub(consumed));
        descriptor
            .bytes
            .extend_from_slice(&input[consumed..consumed + count]);
        consumed += count;
        if descriptor.bytes.len() < target {
            if matches!(end, EndOfInput::End) && consumed == input.len() {
                return Err(Self::error(
                    ErrorKind::Malformed,
                    "truncated ZIP data descriptor",
                ));
            }
            self.state = State::Descriptor(descriptor);
            return Ok(Self::need_input(consumed));
        }
        let base = usize::from(target == signed) * 4;
        let expected_crc = le32(&descriptor.bytes, base)?;
        let (compressed, uncompressed) = if descriptor.zip64 {
            (
                le64(&descriptor.bytes, base + 4)?,
                le64(&descriptor.bytes, base + 12)?,
            )
        } else {
            (
                u64::from(le32(&descriptor.bytes, base + 4)?),
                u64::from(le32(&descriptor.bytes, base + 8)?),
            )
        };
        if expected_crc != descriptor.crc
            || compressed != descriptor.compressed
            || uncompressed != descriptor.uncompressed
        {
            return Err(Self::error(
                ErrorKind::Integrity,
                "ZIP data descriptor disagrees with decoded payload",
            ));
        }
        Ok(self.finish_entry(consumed))
    }

    #[cfg(feature = "gzip")]
    #[allow(clippy::too_many_lines)]
    fn step_deflate64<'a>(
        &mut self,
        mut state: Deflate64State,
        input: &'a [u8],
        output: &'a mut [u8],
        end: EndOfInput,
    ) -> Result<DecodeStep<'a>, ArchiveError> {
        if output.is_empty() {
            self.state = State::Deflate64(state);
            return Ok(DecodeStep {
                consumed: 0,
                produced: 0,
                event: DecodeEvent::NeedOutput,
            });
        }
        let prefetched = if state.descriptor {
            usize::try_from(state.loaded.checked_sub(state.compressed).ok_or_else(|| {
                Self::error(
                    ErrorKind::Protocol,
                    "ZIP Deflate64 committed input exceeds loaded input",
                )
            })?)
            .map_err(|_| {
                Self::error(
                    ErrorKind::Limit,
                    "ZIP Deflate64 look-ahead exceeds address space",
                )
            })?
        } else {
            0
        };
        if prefetched > input.len() {
            return Err(Self::error(
                ErrorKind::Protocol,
                "ZIP Deflate64 look-ahead is missing from pipeline input",
            ));
        }
        if state.compressed_remaining != Some(0) && input.is_empty() {
            if matches!(end, EndOfInput::End) {
                return Err(Self::error(
                    ErrorKind::Malformed,
                    "truncated ZIP Deflate64 payload",
                ));
            }
            self.state = State::Deflate64(state);
            return Ok(Self::need_input(0));
        }
        let available = match state.compressed_remaining {
            Some(remaining) => {
                usize::try_from(remaining.min(input.len() as u64)).map_err(|_| {
                    Self::error(
                        ErrorKind::Limit,
                        "ZIP Deflate64 extent exceeds address space",
                    )
                })?
            },
            None => input.len(),
        };
        let encoded = &input[..available];
        let result = match state.compressed_remaining {
            Some(remaining) => inflate64_extent_step(
                &mut state.decoder,
                encoded,
                remaining - available as u64,
                output,
            ),
            None => state.decoder.inflate(&encoded[prefetched..], output),
        };
        if result.data_error || state.decoder.errored() {
            return Err(Self::error(
                ErrorKind::Malformed,
                "ZIP Deflate64 decoder rejected the bitstream",
            ));
        }
        state.loaded = state
            .loaded
            .checked_add(result.bytes_consumed as u64)
            .ok_or_else(|| Self::error(ErrorKind::Limit, "ZIP loaded input count overflow"))?;
        let consumed = if state.descriptor {
            Self::deflate64_descriptor_consumed(&state.decoder, state.compressed, state.loaded)?
        } else {
            result.bytes_consumed
        };
        state.compressed = state
            .compressed
            .checked_add(consumed as u64)
            .ok_or_else(|| Self::error(ErrorKind::Limit, "ZIP compressed count overflow"))?;
        if !state.descriptor && state.loaded != state.compressed {
            return Err(Self::error(
                ErrorKind::Protocol,
                "known-size ZIP Deflate64 input accounting diverged",
            ));
        }
        if let Some(remaining) = &mut state.compressed_remaining {
            *remaining = remaining.checked_sub(consumed as u64).ok_or_else(|| {
                Self::error(
                    ErrorKind::Protocol,
                    "ZIP Deflate64 decoder over-consumed its extent",
                )
            })?;
        }
        state.produced = state
            .produced
            .checked_add(result.bytes_written as u64)
            .ok_or_else(|| Self::error(ErrorKind::Limit, "ZIP Deflate64 output count overflow"))?;
        state.crc.update(&output[..result.bytes_written]);
        self.account_entry_and_total(state.produced, result.bytes_written)?;

        if state.decoder.finished() {
            if state
                .compressed_remaining
                .is_some_and(|remaining| remaining != 0)
            {
                return Err(Self::error(
                    ErrorKind::Integrity,
                    "ZIP Deflate64 stream ended before its declared extent",
                ));
            }
            if state.descriptor {
                self.state = State::Descriptor(DescriptorState {
                    bytes: Vec::new(),
                    zip64: state.zip64,
                    crc: state.crc.finalize(),
                    compressed: state.compressed,
                    uncompressed: state.produced,
                });
            } else {
                if state.expected_size != Some(state.produced)
                    || state.expected_crc != Some(state.crc.finalize())
                {
                    return Err(Self::error(
                        ErrorKind::Integrity,
                        "ZIP Deflate64 size or CRC32 mismatch",
                    ));
                }
                self.state = State::EndEntry;
            }
        } else {
            if result.bytes_consumed == 0
                && result.bytes_written == 0
                && (state.compressed_remaining == Some(0) || matches!(end, EndOfInput::End))
            {
                return Err(Self::error(
                    ErrorKind::Malformed,
                    "truncated ZIP Deflate64 stream",
                ));
            }
            self.state = State::Deflate64(state);
        }
        if result.bytes_written != 0 {
            return Ok(DecodeStep {
                consumed,
                produced: result.bytes_written,
                event: DecodeEvent::Data(Chunk::new(&output[..result.bytes_written])),
            });
        }
        Ok(Self::need_input(consumed))
    }

    #[cfg(feature = "xz")]
    #[allow(clippy::too_many_lines)]
    fn step_lzma<'a>(
        &mut self,
        mut state: LzmaState,
        input: &'a [u8],
        output: &'a mut [u8],
        end: EndOfInput,
    ) -> Result<DecodeStep<'a>, ArchiveError> {
        if state.decoder.is_none() {
            let needed = state.header.len() - state.header_len;
            let count = match state.compressed_remaining {
                Some(remaining) => needed
                    .min(input.len())
                    .min(usize::try_from(remaining).unwrap_or(usize::MAX)),
                None => needed.min(input.len()),
            };
            state.header[state.header_len..state.header_len + count]
                .copy_from_slice(&input[..count]);
            state.header_len += count;
            if let Some(remaining) = &mut state.compressed_remaining {
                *remaining = remaining.checked_sub(count as u64).ok_or_else(|| {
                    Self::error(
                        ErrorKind::Protocol,
                        "ZIP LZMA header exceeded its declared extent",
                    )
                })?;
            }
            state.compressed = state
                .compressed
                .checked_add(count as u64)
                .ok_or_else(|| Self::error(ErrorKind::Limit, "ZIP compressed count overflow"))?;
            if state.header_len != state.header.len() {
                if matches!(end, EndOfInput::End) && count == input.len() {
                    return Err(Self::error(
                        ErrorKind::Malformed,
                        "truncated ZIP LZMA header",
                    ));
                }
                self.state = State::Lzma(state);
                return Ok(Self::need_input(count));
            }
            if u16::from_le_bytes([state.header[2], state.header[3]]) != 5 {
                return Err(Self::error(
                    ErrorKind::Malformed,
                    "ZIP LZMA property size is not 5",
                ));
            }
            let properties = state.header[4];
            let dictionary = u32::from_le_bytes(
                state.header[5..9]
                    .try_into()
                    .map_err(|_| Self::error(ErrorKind::Protocol, "ZIP LZMA header vanished"))?,
            );
            state.decoder = Some(Box::new(if state.descriptor {
                LzipDecoder::new_zip_lzma_checkpointed(self.limits, properties, dictionary)?
            } else {
                let declared_size = if state.end_marker {
                    u64::MAX
                } else {
                    state.expected_size.ok_or_else(|| {
                        Self::error(
                            ErrorKind::Protocol,
                            "known-size ZIP LZMA entry lost its decoded size",
                        )
                    })?
                };
                LzipDecoder::new_zip_lzma(self.limits, properties, dictionary, declared_size)?
            }));
            self.state = State::Lzma(state);
            return Ok(Self::need_input(count));
        }
        if output.is_empty() {
            self.state = State::Lzma(state);
            return Ok(DecodeStep {
                consumed: 0,
                produced: 0,
                event: DecodeEvent::NeedOutput,
            });
        }
        if input.is_empty()
            && state.compressed_remaining != Some(0)
            && matches!(end, EndOfInput::End)
        {
            return Err(Self::error(
                ErrorKind::Malformed,
                "truncated ZIP LZMA payload",
            ));
        }
        let available = match state.compressed_remaining {
            Some(remaining) => {
                usize::try_from(remaining.min(input.len() as u64)).map_err(|_| {
                    Self::error(ErrorKind::Limit, "ZIP LZMA extent exceeds address space")
                })?
            },
            None => input.len(),
        };
        let codec_end = match state.compressed_remaining {
            Some(remaining) if remaining == available as u64 => EndOfInput::End,
            Some(_) | None => EndOfInput::More,
        };
        let codec = state
            .decoder
            .as_mut()
            .ok_or_else(|| Self::error(ErrorKind::Protocol, "ZIP LZMA decoder disappeared"))?
            .process(&input[..available], output, codec_end)?
            .validate(available, output.len())?;
        if let Some(remaining) = &mut state.compressed_remaining {
            *remaining = remaining
                .checked_sub(codec.consumed as u64)
                .ok_or_else(|| {
                    Self::error(
                        ErrorKind::Protocol,
                        "ZIP LZMA decoder over-consumed its extent",
                    )
                })?;
        }
        state.compressed = state
            .compressed
            .checked_add(codec.consumed as u64)
            .ok_or_else(|| Self::error(ErrorKind::Limit, "ZIP compressed count overflow"))?;
        state.produced = state
            .produced
            .checked_add(codec.produced as u64)
            .ok_or_else(|| Self::error(ErrorKind::Limit, "ZIP LZMA output count overflow"))?;
        state.crc.update(&output[..codec.produced]);
        self.account_entry_and_total(state.produced, codec.produced)?;

        if codec.status == CodecStatus::Done {
            if state.descriptor {
                self.state = State::Descriptor(DescriptorState {
                    bytes: Vec::new(),
                    zip64: state.zip64,
                    crc: state.crc.finalize(),
                    compressed: state.compressed,
                    uncompressed: state.produced,
                });
            } else {
                if state.expected_size != Some(state.produced)
                    || state.expected_crc != Some(state.crc.finalize())
                {
                    return Err(Self::error(
                        ErrorKind::Integrity,
                        "ZIP LZMA size or CRC32 mismatch",
                    ));
                }
                let remaining = state.compressed_remaining.ok_or_else(|| {
                    Self::error(
                        ErrorKind::Protocol,
                        "known-size ZIP LZMA entry lost its compressed extent",
                    )
                })?;
                self.state = if remaining == 0 {
                    State::EndEntry
                } else {
                    State::LzmaTail(remaining)
                };
            }
        } else {
            if !matches!(
                codec.status,
                CodecStatus::NeedInput | CodecStatus::NeedOutput
            ) {
                return Err(Self::error(
                    ErrorKind::Protocol,
                    "ZIP LZMA decoder returned an unknown status",
                ));
            }
            if codec.consumed == 0 && codec.produced == 0 && matches!(codec_end, EndOfInput::End) {
                return Err(Self::error(
                    ErrorKind::Malformed,
                    "truncated ZIP LZMA stream",
                ));
            }
            self.state = State::Lzma(state);
        }
        if codec.produced != 0 {
            return Ok(DecodeStep {
                consumed: codec.consumed,
                produced: codec.produced,
                event: DecodeEvent::Data(Chunk::new(&output[..codec.produced])),
            });
        }
        Ok(Self::need_input(codec.consumed))
    }

    #[cfg(feature = "xz")]
    fn step_lzma_tail<'a>(
        &mut self,
        remaining: u64,
        input: &'a [u8],
        end: EndOfInput,
    ) -> Result<DecodeStep<'a>, ArchiveError> {
        let count = usize::try_from(remaining.min(input.len() as u64))
            .map_err(|_| Self::error(ErrorKind::Limit, "ZIP LZMA tail exceeds address space"))?;
        let remaining = remaining - count as u64;
        if remaining == 0 {
            self.state = State::EndEntry;
        } else {
            if matches!(end, EndOfInput::End) && count == input.len() {
                return Err(Self::error(
                    ErrorKind::Malformed,
                    "truncated ZIP LZMA declared extent",
                ));
            }
            self.state = State::LzmaTail(remaining);
        }
        Ok(Self::need_input(count))
    }

    #[cfg(feature = "ppmd")]
    #[allow(clippy::too_many_lines)]
    fn step_ppmd<'a>(
        &mut self,
        mut state: PpmdState,
        input: &'a [u8],
        output: &'a mut [u8],
        end: EndOfInput,
    ) -> Result<DecodeStep<'a>, ArchiveError> {
        if state.decoder.is_none() {
            let needed = state.header.len() - state.header_len;
            let count = match state.compressed_remaining {
                Some(remaining) => needed
                    .min(input.len())
                    .min(usize::try_from(remaining).unwrap_or(usize::MAX)),
                None => needed.min(input.len()),
            };
            state.header[state.header_len..state.header_len + count]
                .copy_from_slice(&input[..count]);
            state.header_len += count;
            if let Some(remaining) = &mut state.compressed_remaining {
                *remaining = remaining.checked_sub(count as u64).ok_or_else(|| {
                    Self::error(
                        ErrorKind::Protocol,
                        "ZIP PPMd header exceeded its declared extent",
                    )
                })?;
            }
            state.compressed = state
                .compressed
                .checked_add(count as u64)
                .ok_or_else(|| Self::error(ErrorKind::Limit, "ZIP compressed count overflow"))?;
            if state.header_len != state.header.len() {
                if matches!(end, EndOfInput::End) && count == input.len() {
                    return Err(Self::error(
                        ErrorKind::Malformed,
                        "truncated ZIP PPMd parameter header",
                    ));
                }
                self.state = State::Ppmd(state);
                return Ok(Self::need_input(count));
            }
            let parameters = u16::from_le_bytes(state.header);
            state.decoder = Some(Box::new(if state.descriptor {
                LzipDecoder::new_zip_ppmd_checkpointed(self.limits, parameters)?
            } else {
                let declared_size = state.expected_size.ok_or_else(|| {
                    Self::error(
                        ErrorKind::Protocol,
                        "known-size ZIP PPMd entry lost its decoded size",
                    )
                })?;
                LzipDecoder::new_zip_ppmd(self.limits, parameters, declared_size)?
            }));
            self.state = State::Ppmd(state);
            return Ok(Self::need_input(count));
        }
        if output.is_empty() {
            self.state = State::Ppmd(state);
            return Ok(DecodeStep {
                consumed: 0,
                produced: 0,
                event: DecodeEvent::NeedOutput,
            });
        }
        if input.is_empty()
            && state.compressed_remaining != Some(0)
            && matches!(end, EndOfInput::End)
        {
            return Err(Self::error(
                ErrorKind::Malformed,
                "truncated ZIP PPMd payload",
            ));
        }
        let available = match state.compressed_remaining {
            Some(remaining) => {
                usize::try_from(remaining.min(input.len() as u64)).map_err(|_| {
                    Self::error(ErrorKind::Limit, "ZIP PPMd extent exceeds address space")
                })?
            },
            None => input.len(),
        };
        let codec_end = match state.compressed_remaining {
            Some(remaining) if remaining == available as u64 => EndOfInput::End,
            Some(_) | None => EndOfInput::More,
        };
        let codec = state
            .decoder
            .as_mut()
            .ok_or_else(|| Self::error(ErrorKind::Protocol, "ZIP PPMd decoder disappeared"))?
            .process(&input[..available], output, codec_end)?
            .validate(available, output.len())?;
        if let Some(remaining) = &mut state.compressed_remaining {
            *remaining = remaining
                .checked_sub(codec.consumed as u64)
                .ok_or_else(|| {
                    Self::error(
                        ErrorKind::Protocol,
                        "ZIP PPMd decoder over-consumed its extent",
                    )
                })?;
        }
        state.compressed = state
            .compressed
            .checked_add(codec.consumed as u64)
            .ok_or_else(|| Self::error(ErrorKind::Limit, "ZIP compressed count overflow"))?;
        state.crc.update(&output[..codec.produced]);
        state.produced = state
            .produced
            .checked_add(codec.produced as u64)
            .ok_or_else(|| Self::error(ErrorKind::Limit, "ZIP PPMd output count overflow"))?;
        self.account_entry_and_total(state.produced, codec.produced)?;

        if codec.status == CodecStatus::Done {
            if state.descriptor {
                self.state = State::Descriptor(DescriptorState {
                    bytes: Vec::new(),
                    zip64: state.zip64,
                    crc: state.crc.finalize(),
                    compressed: state.compressed,
                    uncompressed: state.produced,
                });
            } else {
                if state.expected_size != Some(state.produced)
                    || state.expected_crc != Some(state.crc.finalize())
                {
                    return Err(Self::error(
                        ErrorKind::Integrity,
                        "ZIP PPMd size or CRC32 mismatch",
                    ));
                }
                let remaining = state.compressed_remaining.ok_or_else(|| {
                    Self::error(
                        ErrorKind::Protocol,
                        "known-size ZIP PPMd entry lost its compressed extent",
                    )
                })?;
                self.state = if remaining == 0 {
                    State::EndEntry
                } else {
                    State::PpmdTail(remaining)
                };
            }
        } else {
            if !matches!(
                codec.status,
                CodecStatus::NeedInput | CodecStatus::NeedOutput
            ) {
                return Err(Self::error(
                    ErrorKind::Protocol,
                    "ZIP PPMd decoder returned an unknown status",
                ));
            }
            if codec.consumed == 0 && codec.produced == 0 && matches!(end, EndOfInput::End) {
                return Err(Self::error(
                    ErrorKind::Malformed,
                    "truncated ZIP PPMd stream",
                ));
            }
            self.state = State::Ppmd(state);
        }
        if codec.produced != 0 {
            return Ok(DecodeStep {
                consumed: codec.consumed,
                produced: codec.produced,
                event: DecodeEvent::Data(Chunk::new(&output[..codec.produced])),
            });
        }
        Ok(Self::need_input(codec.consumed))
    }

    #[cfg(feature = "ppmd")]
    fn step_ppmd_tail<'a>(
        &mut self,
        remaining: u64,
        input: &'a [u8],
        end: EndOfInput,
    ) -> Result<DecodeStep<'a>, ArchiveError> {
        let count = usize::try_from(remaining.min(input.len() as u64))
            .map_err(|_| Self::error(ErrorKind::Limit, "ZIP PPMd tail exceeds address space"))?;
        let remaining = remaining - count as u64;
        if remaining == 0 {
            self.state = State::EndEntry;
        } else {
            if matches!(end, EndOfInput::End) && count == input.len() {
                return Err(Self::error(
                    ErrorKind::Malformed,
                    "truncated ZIP PPMd compressed extent",
                ));
            }
            self.state = State::PpmdTail(remaining);
        }
        Ok(Self::need_input(count))
    }

    #[cfg(any(feature = "zstd", feature = "xz"))]
    #[allow(clippy::too_many_lines)]
    fn step_pipeline<'a>(
        &mut self,
        mut state: PipelineState,
        input: &'a [u8],
        output: &'a mut [u8],
        end: EndOfInput,
    ) -> Result<DecodeStep<'a>, ArchiveError> {
        if output.is_empty() {
            self.state = State::Pipeline(state);
            return Ok(DecodeStep {
                consumed: 0,
                produced: 0,
                event: DecodeEvent::NeedOutput,
            });
        }

        let (available, codec_end) = if let Some(remaining) = state.compressed_remaining {
            if remaining != 0 && input.is_empty() {
                if matches!(end, EndOfInput::End) {
                    return Err(Self::error(
                        ErrorKind::Malformed,
                        format!("truncated ZIP {} payload", state.name),
                    ));
                }
                self.state = State::Pipeline(state);
                return Ok(Self::need_input(0));
            }
            let available = usize::try_from(remaining.min(input.len() as u64)).map_err(|_| {
                Self::error(
                    ErrorKind::Limit,
                    format!("ZIP {} extent exceeds address space", state.name),
                )
            })?;
            let codec_end = if remaining == available as u64 {
                EndOfInput::End
            } else {
                EndOfInput::More
            };
            (available, codec_end)
        } else {
            let (available, frame_complete) = state.boundary.preview(input)?;
            if available == 0 && !frame_complete {
                if matches!(end, EndOfInput::End) {
                    return Err(Self::error(
                        ErrorKind::Malformed,
                        "truncated ZIP Zstandard frame",
                    ));
                }
                self.state = State::Pipeline(state);
                return Ok(Self::need_input(0));
            }
            (
                available,
                if frame_complete {
                    EndOfInput::End
                } else {
                    EndOfInput::More
                },
            )
        };

        let encoded = &input[..available];
        let codec = state
            .decoder
            .process(encoded, output, codec_end)?
            .validate(encoded.len(), output.len())?;
        state.compressed = state
            .compressed
            .checked_add(codec.consumed as u64)
            .ok_or_else(|| Self::error(ErrorKind::Limit, "ZIP compressed count overflow"))?;
        if let Some(remaining) = &mut state.compressed_remaining {
            *remaining = remaining
                .checked_sub(codec.consumed as u64)
                .ok_or_else(|| {
                    Self::error(
                        ErrorKind::Protocol,
                        format!("ZIP {} decoder over-consumed its extent", state.name),
                    )
                })?;
        } else {
            let tracked = state.boundary.consume(&encoded[..codec.consumed])?;
            if tracked != codec.consumed {
                return Err(Self::error(
                    ErrorKind::Protocol,
                    format!("ZIP {} decoder crossed its frame boundary", state.name),
                ));
            }
        }
        state.produced = state
            .produced
            .checked_add(codec.produced as u64)
            .ok_or_else(|| {
                Self::error(
                    ErrorKind::Limit,
                    format!("ZIP {} output count overflow", state.name),
                )
            })?;
        state.crc.update(&output[..codec.produced]);
        self.account_entry_and_total(state.produced, codec.produced)?;

        if codec.status == CodecStatus::Done {
            if state
                .compressed_remaining
                .is_some_and(|remaining| remaining != 0)
            {
                return Err(Self::error(
                    ErrorKind::Integrity,
                    format!("ZIP {} stream ended before its declared extent", state.name),
                ));
            }
            if state.compressed_remaining.is_none() && !state.boundary.done() {
                return Err(Self::error(
                    ErrorKind::Malformed,
                    format!("ZIP {} decoder ended before its frame boundary", state.name),
                ));
            }
            if state.descriptor {
                self.state = State::Descriptor(DescriptorState {
                    bytes: Vec::new(),
                    zip64: state.zip64,
                    crc: state.crc.finalize(),
                    compressed: state.compressed,
                    uncompressed: state.produced,
                });
            } else {
                if state.expected_size != Some(state.produced)
                    || state.expected_crc != Some(state.crc.finalize())
                {
                    return Err(Self::error(
                        ErrorKind::Integrity,
                        format!("ZIP {} size or CRC32 mismatch", state.name),
                    ));
                }
                self.state = State::EndEntry;
            }
        } else {
            if !matches!(
                codec.status,
                CodecStatus::NeedInput | CodecStatus::NeedOutput
            ) {
                return Err(Self::error(
                    ErrorKind::Protocol,
                    format!("ZIP {} decoder returned an unknown status", state.name),
                ));
            }
            let extent_ended = state.compressed_remaining == Some(0) || state.boundary.done();
            if codec.consumed == 0
                && codec.produced == 0
                && (available != 0 || extent_ended || matches!(end, EndOfInput::End))
            {
                return Err(Self::error(
                    ErrorKind::Malformed,
                    format!(
                        "truncated ZIP {} stream or decoder made no progress",
                        state.name
                    ),
                ));
            }
            self.state = State::Pipeline(state);
        }
        if codec.produced != 0 {
            return Ok(DecodeStep {
                consumed: codec.consumed,
                produced: codec.produced,
                event: DecodeEvent::Data(Chunk::new(&output[..codec.produced])),
            });
        }
        Ok(Self::need_input(codec.consumed))
    }

    #[cfg(feature = "bzip2")]
    #[allow(clippy::too_many_lines)]
    fn step_bzip2<'a>(
        &mut self,
        mut state: Bzip2State,
        input: &'a [u8],
        output: &'a mut [u8],
        end: EndOfInput,
    ) -> Result<DecodeStep<'a>, ArchiveError> {
        if output.is_empty() {
            self.state = State::Bzip2(state);
            return Ok(DecodeStep {
                consumed: 0,
                produced: 0,
                event: DecodeEvent::NeedOutput,
            });
        }
        let available = match state.compressed_remaining {
            Some(remaining) => {
                usize::try_from(remaining.min(input.len() as u64)).map_err(|_| {
                    Self::error(ErrorKind::Limit, "ZIP bzip2 extent exceeds address space")
                })?
            },
            None => input.len(),
        };
        if available == 0 {
            if matches!(end, EndOfInput::End) {
                return Err(Self::error(
                    ErrorKind::Malformed,
                    "truncated ZIP bzip2 payload",
                ));
            }
            self.state = State::Bzip2(state);
            return Ok(Self::need_input(0));
        }
        let before_in = state.decoder.total_in();
        let before_out = state.decoder.total_out();
        let status = state
            .decoder
            .decompress(&input[..available], output)
            .map_err(|_| Self::error(ErrorKind::Malformed, "ZIP bzip2 decoder failed"))?;
        if status == bzip2::Status::MemNeeded {
            return Err(Self::error(
                ErrorKind::Limit,
                "ZIP bzip2 decoder ran out of memory",
            ));
        }
        let consumed = usize::try_from(state.decoder.total_in() - before_in)
            .map_err(|_| Self::error(ErrorKind::Limit, "ZIP bzip2 consumed count overflow"))?;
        let produced = usize::try_from(state.decoder.total_out() - before_out)
            .map_err(|_| Self::error(ErrorKind::Limit, "ZIP bzip2 output count overflow"))?;
        state.compressed = state
            .compressed
            .checked_add(consumed as u64)
            .ok_or_else(|| Self::error(ErrorKind::Limit, "ZIP compressed count overflow"))?;
        if let Some(remaining) = &mut state.compressed_remaining {
            *remaining = remaining.checked_sub(consumed as u64).ok_or_else(|| {
                Self::error(
                    ErrorKind::Protocol,
                    "ZIP bzip2 decoder over-consumed its extent",
                )
            })?;
        }
        state.produced = state
            .produced
            .checked_add(produced as u64)
            .ok_or_else(|| Self::error(ErrorKind::Limit, "ZIP bzip2 output count overflow"))?;
        state.crc.update(&output[..produced]);
        self.account_entry_and_total(state.produced, produced)?;

        if status == bzip2::Status::StreamEnd {
            if state
                .compressed_remaining
                .is_some_and(|remaining| remaining != 0)
            {
                return Err(Self::error(
                    ErrorKind::Integrity,
                    "ZIP bzip2 stream ended before its declared extent",
                ));
            }
            if state.descriptor {
                self.state = State::Descriptor(DescriptorState {
                    bytes: Vec::new(),
                    zip64: state.zip64,
                    crc: state.crc.finalize(),
                    compressed: state.compressed,
                    uncompressed: state.produced,
                });
            } else {
                if state.expected_size != Some(state.produced)
                    || state.expected_crc != Some(state.crc.finalize())
                {
                    return Err(Self::error(
                        ErrorKind::Integrity,
                        "ZIP bzip2 size or CRC32 mismatch",
                    ));
                }
                self.state = State::EndEntry;
            }
        } else {
            if consumed == 0 && produced == 0 && matches!(end, EndOfInput::End) {
                return Err(Self::error(
                    ErrorKind::Malformed,
                    "truncated ZIP bzip2 stream",
                ));
            }
            self.state = State::Bzip2(state);
        }
        if produced != 0 {
            return Ok(DecodeStep {
                consumed,
                produced,
                event: DecodeEvent::Data(Chunk::new(&output[..produced])),
            });
        }
        Ok(Self::need_input(consumed))
    }

    fn step_skip<'a>(
        &mut self,
        remaining: u64,
        input: &'a [u8],
        end: EndOfInput,
    ) -> Result<DecodeStep<'a>, ArchiveError> {
        let count = usize::try_from(remaining.min(input.len() as u64))
            .map_err(|_| Self::error(ErrorKind::Limit, "ZIP skip extent exceeds address space"))?;
        let remaining = remaining - count as u64;
        if remaining == 0 {
            self.state = State::Header(HeaderState::new());
        } else {
            if matches!(end, EndOfInput::End) && count == input.len() {
                return Err(Self::error(
                    ErrorKind::Malformed,
                    "truncated ZIP metadata record",
                ));
            }
            self.state = State::Skip(remaining);
        }
        Ok(Self::need_input(count))
    }
}

impl ArchiveDecoder for ZipStreamDecoder {
    fn step<'a>(
        &'a mut self,
        input: &'a [u8],
        output: &'a mut [u8],
        end: EndOfInput,
    ) -> Result<DecodeStep<'a>, ArchiveError> {
        let state = core::mem::replace(&mut self.state, State::Poisoned);
        match state {
            State::Header(header) => self.step_header(header, input, end),
            State::StoredKnown(stored) => self.step_stored_known(stored, input, end),
            State::StoredDescriptor(stored) => {
                self.step_stored_descriptor(stored, input, output, end)
            },
            #[cfg(feature = "aes")]
            State::AesStored(stored) => self.step_aes_stored(stored, input, output, end),
            #[cfg(feature = "aes")]
            State::AesAuthentication(state) => self.step_aes_authentication(state, input, end),
            #[cfg(feature = "aes")]
            State::AesDeflate(state) => self.step_aes_deflate(state, input, output, end),
            #[cfg(all(feature = "aes", feature = "gzip"))]
            State::AesDeflate64(state) => self.step_aes_deflate64(state, input, output, end),
            #[cfg(all(
                feature = "aes",
                any(feature = "bzip2", feature = "zstd", feature = "xz", feature = "ppmd")
            ))]
            State::AesPipeline(state) => self.step_aes_pipeline(state, input, output, end),
            #[cfg(all(feature = "aes", feature = "xz"))]
            State::AesXzPadding(state) => self.step_aes_xz_padding(state, input, end),
            #[cfg(feature = "aes")]
            State::ZipCryptoStored(stored) => {
                self.step_zipcrypto_stored(stored, input, output, end)
            },
            #[cfg(feature = "aes")]
            State::ZipCryptoDeflate(state) => {
                self.step_zipcrypto_deflate(state, input, output, end)
            },
            #[cfg(all(feature = "aes", feature = "gzip"))]
            State::ZipCryptoDeflate64(state) => {
                self.step_zipcrypto_deflate64(state, input, output, end)
            },
            #[cfg(all(
                feature = "aes",
                any(feature = "bzip2", feature = "zstd", feature = "xz", feature = "ppmd")
            ))]
            State::ZipCryptoPipeline(state) => {
                self.step_zipcrypto_pipeline(state, input, output, end)
            },
            #[cfg(all(feature = "aes", feature = "xz"))]
            State::ZipCryptoXzPadding(state) => self.step_zipcrypto_xz_padding(state, input, end),
            State::Deflate(state) => self.step_deflate(state, input, output, end),
            #[cfg(feature = "gzip")]
            State::Deflate64(state) => self.step_deflate64(state, input, output, end),
            #[cfg(feature = "xz")]
            State::Lzma(state) => self.step_lzma(state, input, output, end),
            #[cfg(feature = "xz")]
            State::LzmaTail(remaining) => self.step_lzma_tail(remaining, input, end),
            #[cfg(feature = "ppmd")]
            State::Ppmd(state) => self.step_ppmd(state, input, output, end),
            #[cfg(feature = "ppmd")]
            State::PpmdTail(remaining) => self.step_ppmd_tail(remaining, input, end),
            #[cfg(any(feature = "zstd", feature = "xz"))]
            State::Pipeline(state) => self.step_pipeline(state, input, output, end),
            #[cfg(feature = "bzip2")]
            State::Bzip2(state) => self.step_bzip2(state, input, output, end),
            State::Descriptor(descriptor) => self.step_descriptor(descriptor, input, end),
            State::EndEntry => Ok(self.finish_entry(0)),
            State::Skip(remaining) => self.step_skip(remaining, input, end),
            State::Done => {
                self.state = State::Done;
                Ok(DecodeStep {
                    consumed: 0,
                    produced: 0,
                    event: DecodeEvent::Done,
                })
            },
            State::Poisoned => Err(Self::error(
                ErrorKind::Protocol,
                "ZIP decoder re-entered a poisoned state",
            )),
        }
    }
}

#[cfg(feature = "aes")]
fn advance_zipcrypto(crypto: &mut ZipCrypto, ciphertext: &[u8]) {
    let mut position = 0;
    let mut scratch = [0_u8; 1024];
    while position < ciphertext.len() {
        let count = (ciphertext.len() - position).min(scratch.len());
        scratch[..count].copy_from_slice(&ciphertext[position..position + count]);
        crypto.decrypt(&mut scratch[..count]);
        position += count;
    }
}

#[cfg(feature = "aes")]
fn advance_aes(crypto: &mut ZipAesDecoder, ciphertext: &[u8]) {
    let mut position = 0;
    let mut scratch = [0_u8; 1024];
    while position < ciphertext.len() {
        let count = (ciphertext.len() - position).min(scratch.len());
        scratch[..count].copy_from_slice(&ciphertext[position..position + count]);
        crypto.decrypt(&mut scratch[..count]);
        position += count;
    }
}

#[cfg(feature = "gzip")]
fn inflate64_extent_step(
    state: &mut InflaterManaged,
    input: &[u8],
    compressed_unread: u64,
    output: &mut [u8],
) -> InflateResult {
    if compressed_unread != 0 || input.is_empty() {
        return state.inflate(input, output);
    }

    // Prevent the inflater's bit look-ahead from accepting a byte beyond the declared local-header extent.
    // Retry with the final byte only if the prefix made no progress and did not complete or fail.
    let result = state.inflate(&input[..input.len() - 1], output);
    if result.data_error
        || state.finished()
        || result.bytes_consumed != 0
        || result.bytes_written != 0
    {
        result
    } else {
        state.inflate(input, output)
    }
}

fn valid_stored_descriptor(state: &StoredDescriptor, bytes: &[u8]) -> Option<usize> {
    let length = if state.zip64 { 24 } else { 16 };
    if bytes.len() < length {
        return None;
    }
    let mut crc = state.crc;
    for index in 0..=bytes.len() - length {
        if le32_unchecked(&bytes[index..]) == DESCRIPTOR_SIGNATURE {
            let expected_crc = le32_unchecked(&bytes[index + 4..]);
            let (compressed, uncompressed) = if state.zip64 {
                (
                    le64_unchecked(&bytes[index + 8..]),
                    le64_unchecked(&bytes[index + 16..]),
                )
            } else {
                (
                    u64::from(le32_unchecked(&bytes[index + 8..])),
                    u64::from(le32_unchecked(&bytes[index + 12..])),
                )
            };
            let size = state.produced.checked_add(index as u64);
            if size == Some(compressed)
                && size == Some(uncompressed)
                && crc.finalize() == expected_crc
            {
                return Some(index);
            }
        }
        crc.update(&bytes[index..=index]);
    }
    None
}

fn zip64_local_sizes(
    extra: &[u8],
    compressed: u32,
    uncompressed: u32,
) -> Result<(u64, u64), ArchiveError> {
    let Some(values) = extra_field(extra, 0x0001)? else {
        if compressed == U32_SENTINEL || uncompressed == U32_SENTINEL {
            return Err(ZipStreamDecoder::error(
                ErrorKind::Malformed,
                "ZIP64 local sizes are missing",
            ));
        }
        return Ok((u64::from(compressed), u64::from(uncompressed)));
    };
    let mut position = 0;
    let uncompressed = if uncompressed == U32_SENTINEL {
        let value = le64(values, position)?;
        position += 8;
        value
    } else {
        u64::from(uncompressed)
    };
    let compressed = if compressed == U32_SENTINEL {
        le64(values, position)?
    } else {
        u64::from(compressed)
    };
    Ok((compressed, uncompressed))
}

#[cfg(feature = "aes")]
#[derive(Clone, Copy, Debug)]
struct LocalAesParameters {
    strength: u8,
    method: u16,
    salt_len: usize,
}

#[cfg(feature = "aes")]
fn local_aes_parameters(
    extra: &[u8],
    outer_method: u16,
) -> Result<Option<LocalAesParameters>, ArchiveError> {
    let Some(value) = extra_field(extra, 0x9901)? else {
        if outer_method == 99 {
            return Err(ZipStreamDecoder::error(
                ErrorKind::Malformed,
                "AES method is missing its extra field",
            ));
        }
        return Ok(None);
    };
    if outer_method != 99 || value.len() != 7 || &value[2..4] != b"AE" {
        return Err(ZipStreamDecoder::error(
            ErrorKind::Malformed,
            "invalid WinZip AES extra field",
        ));
    }
    let version = le16(value, 0)?;
    if version != 2 {
        return Err(ZipStreamDecoder::error(
            ErrorKind::Unsupported,
            "forward-only ZIP supports WinZip AES AE-2 only",
        ));
    }
    let strength = value[4];
    let salt_len = match strength {
        1 => 8,
        2 => 12,
        3 => 16,
        _ => {
            return Err(ZipStreamDecoder::error(
                ErrorKind::Malformed,
                "invalid WinZip AES strength code",
            ));
        },
    };
    Ok(Some(LocalAesParameters {
        strength,
        method: le16(value, 5)?,
        salt_len,
    }))
}

fn validate_extra_fields(extra: &[u8]) -> Result<(), ArchiveError> {
    let mut cursor = 0;
    while cursor < extra.len() {
        if extra.len() - cursor < 4 {
            return Err(ZipStreamDecoder::error(
                ErrorKind::Malformed,
                "truncated ZIP extra field header",
            ));
        }
        let length = usize::from(le16(extra, cursor + 2)?);
        cursor = cursor
            .checked_add(4)
            .and_then(|value| value.checked_add(length))
            .ok_or_else(|| {
                ZipStreamDecoder::error(ErrorKind::Limit, "ZIP extra field length overflow")
            })?;
        if cursor > extra.len() {
            return Err(ZipStreamDecoder::error(
                ErrorKind::Malformed,
                "truncated ZIP extra field",
            ));
        }
    }
    Ok(())
}

fn extra_field(extra: &[u8], wanted: u16) -> Result<Option<&[u8]>, ArchiveError> {
    let mut cursor = 0;
    while cursor < extra.len() {
        let id = le16(extra, cursor)?;
        let length = usize::from(le16(extra, cursor + 2)?);
        let start = cursor + 4;
        let finish = start + length;
        if id == wanted {
            return Ok(Some(&extra[start..finish]));
        }
        cursor = finish;
    }
    Ok(None)
}

fn unicode_zip_value<'a>(
    extra: &'a [u8],
    wanted: u16,
    original: &[u8],
) -> Result<Option<&'a [u8]>, ArchiveError> {
    let Some(value) = extra_field(extra, wanted)? else {
        return Ok(None);
    };
    if value.len() < 5 || value[0] != 1 {
        return Ok(None);
    }
    if le32(value, 1)? != crate::filter::crc32(original) {
        return Ok(None);
    }
    core::str::from_utf8(&value[5..]).map_err(|_| {
        ZipStreamDecoder::error(ErrorKind::Malformed, "Unicode ZIP extra is not UTF-8")
    })?;
    Ok(Some(&value[5..]))
}

fn zip_times(extra: &[u8]) -> Result<EntryTimes, ArchiveError> {
    let mut times = EntryTimes::default();
    let mut cursor = 0;
    while cursor < extra.len() {
        let id = le16(extra, cursor)?;
        let length = usize::from(le16(extra, cursor + 2)?);
        let start = cursor + 4;
        let finish = start + length;
        let value = &extra[start..finish];
        match id {
            0x5455 if !value.is_empty() => {
                let flags = value[0];
                let mut position = 1;
                for (bit, destination) in [
                    (0x01, &mut times.modified),
                    (0x02, &mut times.accessed),
                    (0x04, &mut times.changed),
                ] {
                    if flags & bit == 0 {
                        continue;
                    }
                    let seconds = le32(value, position)?;
                    *destination = Some(Timestamp::from_seconds(i64::from(signed_le32(seconds))));
                    position += 4;
                }
            },
            0x000a if value.len() >= 4 => parse_ntfs_times(&value[4..], &mut times)?,
            0x5855 if value.len() >= 8 => {
                times.accessed = Some(Timestamp::from_seconds(i64::from(signed_le32(le32(
                    value, 0,
                )?))));
                times.modified = Some(Timestamp::from_seconds(i64::from(signed_le32(le32(
                    value, 4,
                )?))));
            },
            _ => {},
        }
        cursor = finish;
    }
    Ok(times)
}

fn zip_unix_owner(extra: &[u8]) -> Result<Owner, ArchiveError> {
    let mut owner = Owner::default();
    if let Some(value) = extra_field(extra, 0x7855)?
        && value.len() >= 4
    {
        owner.uid = Some(u64::from(le16(value, 0)?));
        owner.gid = Some(u64::from(le16(value, 2)?));
    }
    Ok(owner)
}

fn parse_ntfs_times(mut tags: &[u8], times: &mut EntryTimes) -> Result<(), ArchiveError> {
    while !tags.is_empty() {
        if tags.len() < 4 {
            return Err(ZipStreamDecoder::error(
                ErrorKind::Malformed,
                "truncated NTFS timestamp tag",
            ));
        }
        let tag = le16(tags, 0)?;
        let size = usize::from(le16(tags, 2)?);
        let end = 4_usize.checked_add(size).ok_or_else(|| {
            ZipStreamDecoder::error(ErrorKind::Limit, "NTFS timestamp tag length overflow")
        })?;
        let value = tags.get(4..end).ok_or_else(|| {
            ZipStreamDecoder::error(ErrorKind::Malformed, "truncated NTFS timestamp value")
        })?;
        if tag == 1 && value.len() >= 24 {
            times.modified = filetime_timestamp(le64(value, 0)?);
            times.accessed = filetime_timestamp(le64(value, 8)?);
            times.created = filetime_timestamp(le64(value, 16)?);
        }
        tags = &tags[end..];
    }
    Ok(())
}

fn filetime_timestamp(ticks: u64) -> Option<Timestamp> {
    const TICKS_PER_SECOND: u64 = 10_000_000;
    const UNIX_EPOCH_SECONDS: i128 = 11_644_473_600;
    if ticks == 0 {
        return None;
    }
    let seconds = i128::from(ticks / TICKS_PER_SECOND) - UNIX_EPOCH_SECONDS;
    Timestamp::new(
        i64::try_from(seconds).ok()?,
        u32::try_from(ticks % TICKS_PER_SECOND)
            .ok()?
            .checked_mul(100)?,
    )
    .ok()
}

fn le16(bytes: &[u8], offset: usize) -> Result<u16, ArchiveError> {
    let value = bytes
        .get(offset..offset + 2)
        .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
        .ok_or_else(|| {
            ZipStreamDecoder::error(ErrorKind::Malformed, "truncated ZIP little-endian u16")
        })?;
    Ok(u16::from_le_bytes(value))
}

fn le32(bytes: &[u8], offset: usize) -> Result<u32, ArchiveError> {
    let value = bytes
        .get(offset..offset + 4)
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .ok_or_else(|| {
            ZipStreamDecoder::error(ErrorKind::Malformed, "truncated ZIP little-endian u32")
        })?;
    Ok(u32::from_le_bytes(value))
}

fn le64(bytes: &[u8], offset: usize) -> Result<u64, ArchiveError> {
    let value = bytes
        .get(offset..offset + 8)
        .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
        .ok_or_else(|| {
            ZipStreamDecoder::error(ErrorKind::Malformed, "truncated ZIP little-endian u64")
        })?;
    Ok(u64::from_le_bytes(value))
}

fn le32_unchecked(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes[..4].try_into().unwrap_or([0; 4]))
}

fn signed_le32(value: u32) -> i32 {
    i32::from_le_bytes(value.to_le_bytes())
}

fn le64_unchecked(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes[..8].try_into().unwrap_or([0; 8]))
}
