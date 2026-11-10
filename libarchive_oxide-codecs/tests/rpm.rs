// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Incremental RPM payload-wrapper decoding and limit contracts.

#![allow(clippy::expect_used, clippy::panic)]

use libarchive_oxide_codecs::rpm::RpmDecoder;
use libarchive_oxide_protocol::{Codec, CodecStatus, EndOfInput, ErrorKind, Limits};

fn header(index_count: u32, store: &[u8], signature: bool) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&[0x8e, 0xad, 0xe8, 1, 0, 0, 0, 0]);
    bytes.extend_from_slice(&index_count.to_be_bytes());
    bytes.extend_from_slice(
        &u32::try_from(store.len())
            .expect("fixture store length")
            .to_be_bytes(),
    );
    bytes.resize(
        bytes.len() + usize::try_from(index_count).expect("fixture index count") * 16,
        0,
    );
    bytes.extend_from_slice(store);
    if signature {
        bytes.resize((bytes.len() + 7) & !7, 0);
    }
    bytes
}

fn rpm(payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0_u8; 96];
    bytes[..4].copy_from_slice(&[0xed, 0xab, 0xee, 0xdb]);
    bytes.extend_from_slice(&header(0, b"pad", true));
    bytes.extend_from_slice(&header(0, b"meta", false));
    bytes.extend_from_slice(payload);
    bytes
}

fn drive(
    input: &[u8],
    input_chunk: usize,
    output_chunk: usize,
    limits: Limits,
) -> Result<Vec<u8>, libarchive_oxide_protocol::ArchiveError> {
    let mut decoder = RpmDecoder::new(limits);
    let mut position = 0;
    let mut output = Vec::new();
    loop {
        let available = (position + input_chunk).min(input.len());
        let end = if available == input.len() {
            EndOfInput::End
        } else {
            EndOfInput::More
        };
        let mut buffer = vec![0_u8; output_chunk];
        let step = decoder
            .process(&input[position..available], &mut buffer, end)?
            .validate(available - position, buffer.len())?;
        position += step.consumed;
        output.extend_from_slice(&buffer[..step.produced]);
        if step.status == CodecStatus::Done {
            assert_eq!(position, input.len());
            return Ok(output);
        }
    }
}

#[test]
fn unwraps_payload_at_every_small_chunk_boundary() {
    let payload = b"\x1f\x8bcompressed-cpio-payload";
    let encoded = rpm(payload);
    for input_chunk in 1..=17 {
        for output_chunk in 1..=7 {
            assert_eq!(
                drive(&encoded, input_chunk, output_chunk, Limits::safe())
                    .expect("decode RPM wrapper"),
                payload
            );
        }
    }
    let mut empty = vec![0_u8; 96];
    empty[..4].copy_from_slice(&[0xed, 0xab, 0xee, 0xdb]);
    empty.extend_from_slice(&header(0, b"", true));
    empty.extend_from_slice(&header(0, b"", false));
    assert_eq!(
        drive(&empty, empty.len(), 1, Limits::safe()).expect("empty RPM payload"),
        b""
    );
}

#[test]
fn rejects_truncation_and_invalid_structure() {
    let encoded = rpm(b"payload");
    for cut in 0..encoded.len() - b"payload".len() {
        let error = drive(&encoded[..cut], 3, 5, Limits::safe())
            .expect_err("truncated RPM header must fail");
        assert_eq!(error.kind(), ErrorKind::Malformed, "cut={cut}");
    }

    let mut bad_lead = encoded.clone();
    bad_lead[0] = 0;
    assert_eq!(
        drive(&bad_lead, 5, 5, Limits::safe())
            .expect_err("invalid lead")
            .kind(),
        ErrorKind::Malformed
    );

    let mut bad_header = encoded;
    bad_header[96] = 0;
    assert_eq!(
        drive(&bad_header, 5, 5, Limits::safe())
            .expect_err("invalid signature header")
            .kind(),
        ErrorKind::Malformed
    );

    let mut bad_reserved = rpm(b"payload");
    bad_reserved[100] = 1;
    assert_eq!(
        drive(&bad_reserved, 5, 5, Limits::safe())
            .expect_err("non-zero header reserved bytes")
            .kind(),
        ErrorKind::Malformed
    );
}

#[test]
fn rejects_header_bombs_before_body_and_bounds_payload_output() {
    let mut oversized = vec![0_u8; 96];
    oversized[..4].copy_from_slice(&[0xed, 0xab, 0xee, 0xdb]);
    oversized.extend_from_slice(&header(1, &[], true));
    assert_eq!(
        drive(
            &oversized,
            oversized.len(),
            8,
            Limits::safe().with_metadata_bytes(Some(15)),
        )
        .expect_err("header index exceeds metadata budget")
        .kind(),
        ErrorKind::Limit
    );

    assert_eq!(
        drive(
            &rpm(b"four"),
            64,
            8,
            Limits::safe().with_decoded_total(Some(3)),
        )
        .expect_err("payload output exceeds decoded limit")
        .kind(),
        ErrorKind::Limit
    );
}
