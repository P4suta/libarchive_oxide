// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Streaming outer-filter `Read` contracts.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::{self, Cursor, Read, Write};

use libarchive_oxide::FilterReader;
use libarchive_oxide::filter::gzip::GzipEncoder;
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

#[test]
fn every_outer_filter_decodes_from_one_byte_reads() {
    let plain = vec![0x5a; 300_000];
    for filter in [FilterId::Gzip, FilterId::Zstd, FilterId::Xz, FilterId::Lz4] {
        let encoded = compress(&plain, filter).unwrap();
        assert_eq!(decode(encoded).unwrap(), plain, "{filter:?}");
    }
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
    for filter in [FilterId::Gzip, FilterId::Zstd, FilterId::Xz, FilterId::Lz4] {
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
fn decoded_output_limit_applies_to_plain_and_filtered_streams() {
    let limits = Limits::default().with_decoded_total(Some(4));
    for bytes in [
        b"12345".to_vec(),
        compress(b"12345", FilterId::Gzip).unwrap(),
    ] {
        let mut reader = FilterReader::with_limits(OneByte::new(bytes), limits).unwrap();
        let mut output = Vec::new();
        assert_eq!(
            reader.read_to_end(&mut output).unwrap_err().kind(),
            io::ErrorKind::Other
        );
        assert_eq!(output, b"1234");
    }
}
