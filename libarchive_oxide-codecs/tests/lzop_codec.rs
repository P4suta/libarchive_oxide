// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Portable lzop codec contract tests.

#![cfg(feature = "lzo")]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use libarchive_oxide_codecs::lzop::{LzopDecoder, LzopEncoder};
use libarchive_oxide_protocol::{Codec, CodecStatus, EndOfInput, ErrorKind, Limits};

const MAGIC: &[u8; 9] = b"\x89LZO\0\r\n\x1a\n";

fn adler32(bytes: &[u8]) -> u32 {
    const MOD: u32 = 65_521;
    let (mut a, mut b) = (1_u32, 0_u32);
    for &byte in bytes {
        a = (a + u32::from(byte)) % MOD;
        b = (b + a) % MOD;
    }
    (b << 16) | a
}

fn header() -> Vec<u8> {
    let mut bytes = Vec::from(MAGIC.as_slice());
    bytes.extend_from_slice(&0x1030_u16.to_be_bytes());
    bytes.extend_from_slice(&0x0940_u16.to_be_bytes());
    bytes.extend_from_slice(&0x0940_u16.to_be_bytes());
    bytes.extend_from_slice(&[1, 5]);
    bytes.extend_from_slice(&0x0300_000d_u32.to_be_bytes());
    bytes.extend_from_slice(&0o100_644_u32.to_be_bytes());
    bytes.extend_from_slice(&0_u32.to_be_bytes());
    bytes.extend_from_slice(&0_u32.to_be_bytes());
    bytes.push(0);
    let checksum = adler32(&bytes[MAGIC.len()..]);
    bytes.extend_from_slice(&checksum.to_be_bytes());
    bytes
}

fn compressed_fixture() -> Vec<u8> {
    // Independent raw LZO1X stream: one literal A, a two-byte distance-one match, then a 97-byte distance-one M3 match, followed by EOS.
    let raw = [18, b'A', 0, 0, 32, 64, 0, 0, 17, 0, 0];
    let plain = [b'A'; 100];
    let mut bytes = header();
    bytes.extend_from_slice(&100_u32.to_be_bytes());
    bytes.extend_from_slice(
        &u32::try_from(raw.len())
            .expect("fixture length fits u32")
            .to_be_bytes(),
    );
    bytes.extend_from_slice(&adler32(&plain).to_be_bytes());
    bytes.extend_from_slice(&raw);
    bytes.extend_from_slice(&0_u32.to_be_bytes());
    bytes
}

fn drive<C: Codec>(
    mut codec: C,
    input: &[u8],
    in_chunk: usize,
    out_chunk: usize,
) -> Result<Vec<u8>, libarchive_oxide_protocol::ArchiveError> {
    let mut input_pos = 0;
    let mut output = vec![0; out_chunk];
    let mut result = Vec::new();
    loop {
        let supplied = (input.len() - input_pos).min(in_chunk);
        let current = &input[input_pos..input_pos + supplied];
        let end = if input_pos + supplied == input.len() {
            EndOfInput::End
        } else {
            EndOfInput::More
        };
        let step = codec
            .process(current, &mut output, end)?
            .validate(current.len(), output.len())?;
        input_pos += step.consumed;
        result.extend_from_slice(&output[..step.produced]);
        if step.status == CodecStatus::Done {
            assert_eq!(input_pos, input.len());
            return Ok(result);
        }
        assert_ne!((step.consumed, step.produced), (0, 0), "codec stalled");
    }
}

#[test]
fn decodes_compressed_lzo1x_blocks_incrementally() {
    let decoded = drive(
        LzopDecoder::new(Limits::safe()),
        &compressed_fixture(),
        1,
        3,
    )
    .expect("decode compressed lzop fixture");
    assert_eq!(decoded, [b'A'; 100]);
}

#[test]
fn stored_writer_is_deterministic_and_round_trips() {
    let plain = b"portable lzop stored blocks remain interoperable".repeat(10_000);
    let encoded = drive(LzopEncoder::new(Limits::safe()).unwrap(), &plain, 7, 11)
        .expect("encode stored lzop stream");
    assert!(encoded.starts_with(MAGIC));
    assert_eq!(
        drive(LzopDecoder::new(Limits::safe()), &encoded, 5, 13).unwrap(),
        plain
    );
    assert_eq!(
        encoded,
        drive(
            LzopEncoder::new(Limits::safe()).unwrap(),
            &plain,
            plain.len(),
            encoded.len()
        )
        .unwrap()
    );
}

#[test]
fn rejects_checksum_mismatch_and_truncation() {
    let fixture = compressed_fixture();
    let mut corrupt = fixture.clone();
    corrupt[46] ^= 1;
    assert_eq!(
        drive(LzopDecoder::new(Limits::safe()), &corrupt, 64, 64)
            .unwrap_err()
            .kind(),
        ErrorKind::Malformed
    );
    for cut in [0, 8, 20, 37, fixture.len() - 1] {
        assert_eq!(
            drive(LzopDecoder::new(Limits::safe()), &fixture[..cut], 9, 8)
                .unwrap_err()
                .kind(),
            ErrorKind::Malformed,
            "cut={cut}"
        );
    }
}

#[test]
fn enforces_decoded_and_workspace_limits_before_block_allocation() {
    let fixture = compressed_fixture();
    assert_eq!(
        drive(
            LzopDecoder::new(Limits::safe().with_decoded_total(Some(99))),
            &fixture,
            fixture.len(),
            128,
        )
        .unwrap_err()
        .kind(),
        ErrorKind::Limit
    );
    assert_eq!(
        drive(
            LzopDecoder::new(Limits::safe().with_codec_memory(Some(100))),
            &fixture,
            fixture.len(),
            128,
        )
        .unwrap_err()
        .kind(),
        ErrorKind::Limit
    );
    assert_eq!(
        LzopEncoder::new(Limits::safe().with_codec_memory(Some(0)))
            .unwrap_err()
            .kind(),
        ErrorKind::Limit
    );
}
