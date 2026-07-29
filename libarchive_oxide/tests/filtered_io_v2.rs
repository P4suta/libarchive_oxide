// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Streaming outer-filter `Read` contracts.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::{self, Cursor, Read, Write};

use libarchive_oxide::filter::gzip::GzipEncoder;
#[cfg(all(feature = "portable-codecs", feature = "native-codecs"))]
use libarchive_oxide::{ArchiveWriter, BackendPreference};
use libarchive_oxide::{FilterReader, filter_for_name};
use libarchive_oxide_core::filter::FilterId;
use libarchive_oxide_core::{Codec, CodecStatus, EndOfInput, Limits};

fn compress(plain: &[u8], filter: FilterId) -> io::Result<Vec<u8>> {
    match filter {
        FilterId::Gzip => {
            let mut codec = GzipEncoder::new(Limits::default());
            let mut input = plain;
            let mut buffer = [0_u8; 257];
            let mut output = Vec::new();
            loop {
                let step = codec
                    .process(input, &mut buffer, EndOfInput::End)
                    .map_err(io::Error::other)?;
                input = &input[step.consumed..];
                output.extend_from_slice(&buffer[..step.produced]);
                if matches!(step.status, CodecStatus::Done) {
                    return Ok(output);
                }
            }
        },
        FilterId::Bzip2 => {
            #[cfg(feature = "bzip2")]
            {
                let mut writer =
                    bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
                writer.write_all(plain)?;
                writer.finish()
            }
            #[cfg(not(feature = "bzip2"))]
            {
                Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "bzip2 feature is disabled",
                ))
            }
        },
        FilterId::Zstd => zstd_codec::stream::encode_all(Cursor::new(plain), 3),
        FilterId::Xz => {
            let mut writer =
                lzma_rust2::XzWriter::new(Vec::new(), lzma_rust2::XzOptions::with_preset(6))?;
            writer.write_all(plain)?;
            writer.finish()
        },
        FilterId::Lz4 => {
            let mut writer = lz4_flex::frame::FrameEncoder::new(Vec::new());
            writer.write_all(plain)?;
            writer
                .finish()
                .map_err(|error| io::Error::other(error.to_string()))
        },
        _ => Err(io::Error::new(io::ErrorKind::Unsupported, "unknown filter")),
    }
}

struct OneByte {
    bytes: Vec<u8>,
    position: usize,
}

impl OneByte {
    fn new(bytes: Vec<u8>) -> Self {
        Self { bytes, position: 0 }
    }
}

impl Read for OneByte {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() || self.position == self.bytes.len() {
            return Ok(0);
        }
        output[0] = self.bytes[self.position];
        self.position += 1;
        Ok(1)
    }
}

fn decode(bytes: Vec<u8>) -> io::Result<Vec<u8>> {
    let mut reader = FilterReader::new(OneByte::new(bytes))?;
    let mut output = Vec::new();
    reader.read_to_end(&mut output)?;
    Ok(output)
}

/// Outer filters available in the current additive feature set.
fn enabled_outer_filters() -> Vec<FilterId> {
    [FilterId::Gzip, FilterId::Zstd, FilterId::Xz, FilterId::Lz4]
        .into_iter()
        .chain(cfg!(feature = "bzip2").then_some(FilterId::Bzip2))
        .collect()
}

#[cfg(all(feature = "portable-codecs", feature = "native-codecs"))]
fn decode_with_backend(bytes: Vec<u8>, backend: BackendPreference) -> io::Result<Vec<u8>> {
    let mut reader = FilterReader::with_backend(OneByte::new(bytes), Limits::default(), backend)?;
    let mut output = Vec::new();
    reader.read_to_end(&mut output)?;
    Ok(output)
}

#[test]
#[cfg(all(feature = "portable-codecs", feature = "native-codecs"))]
fn portable_and_native_backends_decode_independent_frames() {
    let plain: Vec<u8> = (0_u8..=251).cycle().take(300_000).collect();
    for filter in [
        FilterId::Gzip,
        FilterId::Bzip2,
        FilterId::Zstd,
        FilterId::Xz,
        FilterId::Lz4,
    ] {
        let encoded = compress(&plain, filter).unwrap();
        for backend in [BackendPreference::Portable, BackendPreference::Native] {
            assert_eq!(
                decode_with_backend(encoded.clone(), backend).unwrap(),
                plain,
                "{filter:?} with {backend:?}"
            );
        }
    }
}

#[test]
#[cfg(all(feature = "portable-codecs", feature = "native-codecs"))]
fn portable_and_native_writers_interoperate_with_both_readers() {
    let plain = ArchiveWriter::new(Vec::new()).finish().unwrap();
    for filter in [
        FilterId::Gzip,
        FilterId::Bzip2,
        FilterId::Zstd,
        FilterId::Xz,
        FilterId::Lz4,
    ] {
        for writer_backend in [BackendPreference::Portable, BackendPreference::Native] {
            let encoded = ArchiveWriter::with_filter_and_backend(
                Vec::new(),
                libarchive_oxide_core::FormatId::Tar,
                Some(filter),
                Limits::default(),
                writer_backend,
            )
            .unwrap()
            .finish()
            .unwrap();
            for reader_backend in [BackendPreference::Portable, BackendPreference::Native] {
                assert_eq!(
                    decode_with_backend(encoded.clone(), reader_backend).unwrap(),
                    plain,
                    "{filter:?}: {writer_backend:?} -> {reader_backend:?}"
                );
            }
        }
    }
}

#[test]
fn every_outer_filter_decodes_from_one_byte_reads() {
    let plain = vec![0x5a; 300_000];
    for filter in enabled_outer_filters() {
        let encoded = compress(&plain, filter).unwrap();
        assert_eq!(decode(encoded).unwrap(), plain, "{filter:?}");
    }
}

#[test]
fn linked_lz4_blocks_decode_from_one_byte_reads() {
    let plain: Vec<u8> = (0_u8..=251).cycle().take(300_000).collect();
    let info = lz4_flex::frame::FrameInfo::new()
        .content_size(Some(plain.len() as u64))
        .block_size(lz4_flex::frame::BlockSize::Max64KB)
        .block_mode(lz4_flex::frame::BlockMode::Linked)
        .block_checksums(true)
        .content_checksum(true);
    let mut writer = lz4_flex::frame::FrameEncoder::with_frame_info(info, Vec::new());
    writer.write_all(&plain).unwrap();
    let encoded = writer.finish().unwrap();

    assert_eq!(decode(encoded).unwrap(), plain);
}

#[test]
fn gzip_members_concatenate_and_trailing_data_is_rejected() {
    let mut members = compress(b"first", FilterId::Gzip).unwrap();
    members.extend_from_slice(&compress(b"second", FilterId::Gzip).unwrap());
    assert_eq!(decode(members).unwrap(), b"firstsecond");

    let mut trailing = compress(b"body", FilterId::Gzip).unwrap();
    trailing.push(0);
    assert_eq!(
        decode(trailing).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
}

#[test]
fn every_filter_concatenates_members_and_rejects_trailing_data() {
    for filter in enabled_outer_filters() {
        let mut members = compress(b"first", filter).unwrap();
        members.extend_from_slice(&compress(b"second", filter).unwrap());
        assert_eq!(decode(members).unwrap(), b"firstsecond", "{filter:?}");

        let mut trailing = compress(b"body", filter).unwrap();
        trailing.push(0);
        assert_eq!(
            decode(trailing).unwrap_err().kind(),
            io::ErrorKind::InvalidData,
            "{filter:?}"
        );
    }
}

#[test]
#[cfg(feature = "bzip2")]
fn bzip2_accepts_an_independent_python_fixture_and_rejects_corruption() {
    // Produced by Python 3's stdlib `bz2.compress(b"independent-producer", 6)`.
    const PYTHON_BZ2: &[u8] = &[
        0x42, 0x5a, 0x68, 0x36, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59, 0x32, 0x96, 0xa7, 0x1a, 0x00,
        0x00, 0x04, 0x91, 0x80, 0x00, 0x02, 0x0e, 0x21, 0xd6, 0x00, 0x20, 0x00, 0x31, 0x00, 0xd3,
        0x4d, 0x04, 0x34, 0x8d, 0x3c, 0x28, 0xe1, 0xa4, 0xcd, 0x18, 0xe0, 0xc1, 0x07, 0x91, 0xf8,
        0xbb, 0x92, 0x29, 0xc2, 0x84, 0x81, 0x94, 0xb5, 0x38, 0xd0,
    ];
    assert_eq!(
        decode(PYTHON_BZ2.to_vec()).unwrap(),
        b"independent-producer"
    );
    assert_eq!(
        compress(b"independent-producer", FilterId::Bzip2).unwrap(),
        PYTHON_BZ2
    );

    let mut corrupt = PYTHON_BZ2.to_vec();
    let last = corrupt.last_mut().unwrap();
    *last ^= 0x80;
    assert!(decode(corrupt).is_err());

    assert!(decode(b"BZh0malformed".to_vec()).is_err());
    assert!(decode(PYTHON_BZ2[..PYTHON_BZ2.len() - 3].to_vec()).is_err());
}

#[test]
#[cfg(feature = "compress")]
fn compress_lzw_accepts_independent_fixture_and_rejects_bad_headers() {
    // Produced independently by:
    // `printf "hello world" | compress -c | xxd -p`.
    const COMPRESS_HELLO_WORLD: &[u8] = &[
        0x1f, 0x9d, 0x90, 0x68, 0xca, 0xb0, 0x61, 0xf3, 0x06, 0xc4, 0x9d, 0x37, 0x72, 0xd8, 0x90,
        0x01,
    ];

    assert_eq!(
        decode(COMPRESS_HELLO_WORLD.to_vec()).unwrap(),
        b"hello world"
    );

    let mut reserved_bits = COMPRESS_HELLO_WORLD.to_vec();
    reserved_bits[2] |= 0x60;
    assert_eq!(
        decode(reserved_bits).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(
        decode(vec![0x1f, 0x9d]).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );

    let error = FilterReader::with_limits(
        Cursor::new(COMPRESS_HELLO_WORLD),
        Limits::default().with_codec_memory(Some(1)),
    )
    .expect_err("LZW dictionary must be rejected before allocation");
    assert_eq!(error.kind(), io::ErrorKind::OutOfMemory);
}

#[test]
#[cfg(all(
    feature = "compress",
    feature = "portable-codecs",
    feature = "native-codecs"
))]
fn compress_lzw_has_an_explicit_portable_backend_only() {
    const COMPRESS_HELLO: &[u8] = &[0x1f, 0x9d, 0x90, 0x68, 0xca, 0xb0, 0x61, 0xf3, 0x06];
    assert_eq!(
        decode_with_backend(COMPRESS_HELLO.to_vec(), BackendPreference::Portable).unwrap(),
        b"hello"
    );
    assert_eq!(
        decode_with_backend(COMPRESS_HELLO.to_vec(), BackendPreference::Native)
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );
}

#[test]
fn malformed_zstd_block_does_not_panic() {
    // Minimized by the codec_zstd fuzz target after mutating a valid frame.
    const MALFORMED: &[u8] =
        include_bytes!("fixtures/zstd/crash-142bc61adb972f47b2d1ef33ae89832307ea82d5.zst");
    const CORPUS: &[u8] =
        include_bytes!("../../fuzz/corpus/codec_zstd/142bc61adb972f47b2d1ef33ae89832307ea82d5");
    assert_eq!(MALFORMED, CORPUS);

    let mut reader = FilterReader::new(Cursor::new(MALFORMED)).unwrap();
    let mut output = Vec::new();
    assert_eq!(
        reader.read_to_end(&mut output).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );

    let mut retry = [0_u8; 1];
    assert_eq!(
        reader.read(&mut retry).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
}

#[test]
fn decoded_output_limit_applies_to_plain_and_filtered_streams() {
    let limits = Limits::default().with_decoded_total(Some(4));
    let mut inputs = vec![b"12345".to_vec()];
    for filter in enabled_outer_filters() {
        inputs.push(compress(b"12345", filter).unwrap());
    }
    for bytes in inputs {
        let mut reader = FilterReader::with_limits(OneByte::new(bytes), limits).unwrap();
        let mut output = Vec::new();
        assert_eq!(
            reader.read_to_end(&mut output).unwrap_err().kind(),
            io::ErrorKind::Other
        );
        assert_eq!(output, b"1234");
    }
}

#[test]
fn bzip2_filename_conventions_are_detected_case_insensitively() {
    for name in ["archive.bz2", "archive.tbz", "archive.tbz2", "ARCHIVE.TBZ2"] {
        assert_eq!(filter_for_name(name), Some(FilterId::Bzip2), "{name}");
    }
}

#[test]
fn compress_filename_conventions_are_detected_case_insensitively() {
    for name in ["archive.Z", "archive.z", "ARCHIVE.Z"] {
        assert_eq!(filter_for_name(name), Some(FilterId::Compress), "{name}");
    }
}

#[test]
fn xz_dictionary_limit_prevents_oversized_allocation() {
    let encoded = [
        253, 55, 122, 88, 90, 0, 0, 4, 230, 214, 180, 70, 0, 208, 208, 208, 208, 1, 32, 208, 208,
        208, 208, 58, 26, 8, 206, 118, 199, 229, 233, 111, 229, 163, 224, 0, 175, 0, 49, 0, 58, 26,
        8, 93, 206, 118, 199, 214, 233, 229, 7, 52, 195, 209, 14, 191, 206, 85, 103, 251, 2, 0, 0,
        0, 0, 4, 89, 90,
    ];
    let mut reader = FilterReader::with_limits(Cursor::new(encoded), Limits::default()).unwrap();
    let mut output = [0_u8; 1];
    assert_eq!(
        reader.read(&mut output).unwrap_err().kind(),
        io::ErrorKind::OutOfMemory
    );
    assert_eq!(
        reader.read(&mut output).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
}
