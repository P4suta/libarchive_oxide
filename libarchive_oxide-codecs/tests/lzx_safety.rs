// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Safety regressions for the audited CAB-framed regular-LZX fork.

#![cfg(feature = "lzx")]
#![allow(missing_docs)]
#![allow(clippy::expect_used)]

use libarchive_oxide_codecs::lzx::{DecodeFailed, LzxDecoder, MAX_CHUNK_SIZE, WindowSize};

const UNCOMPRESSED_ABC: &[u8] = &[
    0x00, 0x30, 0x30, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    b'a', b'b', b'c', 0x00,
];

fn uncompressed_block(data: &[u8], include_stream_header: bool) -> Vec<u8> {
    let mut bits = Vec::new();
    if include_stream_header {
        bits.push(false); // E8 translation disabled.
    }
    for shift in (0..3).rev() {
        bits.push((0b011_u32 & (1 << shift)) != 0);
    }
    let size = u32::try_from(data.len()).expect("test block length fits LZX's 24-bit field");
    for shift in (0..24).rev() {
        bits.push((size & (1 << shift)) != 0);
    }
    while bits.len() % 16 != 0 {
        bits.push(false);
    }

    let mut encoded = Vec::new();
    for word_bits in bits.chunks_exact(16) {
        let mut word = 0_u16;
        for bit in word_bits {
            word = (word << 1) | u16::from(*bit);
        }
        encoded.extend_from_slice(&word.to_le_bytes());
    }
    for _ in 0..3 {
        encoded.extend_from_slice(&1_u32.to_le_bytes());
    }
    encoded.extend_from_slice(data);
    if (data.len() & 1) != 0 {
        encoded.push(0);
    }
    encoded
}

#[test]
fn uncompressed_chunk_round_trips() {
    let mut decoder = LzxDecoder::new(WindowSize::KB32).expect("bounded decoder allocation");
    let output = decoder
        .decompress_next(UNCOMPRESSED_ABC, 3)
        .expect("valid uncompressed LZX chunk");
    assert_eq!(output, b"abc");
}

#[test]
fn truncated_uncompressed_chunk_is_typed_instead_of_panicking() {
    let mut decoder = LzxDecoder::new(WindowSize::KB32).expect("bounded decoder allocation");
    let error = decoder
        .decompress_next(&UNCOMPRESSED_ABC[..16], 3)
        .expect_err("missing raw bytes must fail");
    assert_eq!(error.reason(), DecodeFailed::UnexpectedEof);
}

#[test]
fn an_element_cannot_cross_the_declared_chunk_boundary() {
    let mut decoder = LzxDecoder::new(WindowSize::KB32).expect("bounded decoder allocation");
    let error = decoder
        .decompress_next(UNCOMPRESSED_ABC, 2)
        .expect_err("three-byte raw element cannot fit a two-byte chunk");
    assert_eq!(error.reason(), DecodeFailed::OverreadChunk);
}

#[test]
fn odd_uncompressed_padding_stays_with_its_cab_frame() {
    let mut first_frame = uncompressed_block(b"x", true);
    let tail = vec![b'y'; MAX_CHUNK_SIZE - 1];
    first_frame.extend_from_slice(&uncompressed_block(&tail, false));
    let second_frame = uncompressed_block(b"end", false);
    let mut decoder = LzxDecoder::new(WindowSize::KB32).expect("bounded decoder allocation");

    let first = decoder
        .decompress_next(&first_frame, MAX_CHUNK_SIZE)
        .expect("two uncompressed blocks fill the first CAB frame");
    assert_eq!(first[0], b'x');
    assert!(first[1..].iter().all(|byte| *byte == b'y'));

    let second = decoder
        .decompress_next(&second_frame, 3)
        .expect("the prior block's pad must not consume this frame's header");
    assert_eq!(second, b"end");
}

#[test]
fn cab_window_sizes_have_exact_memory_values() {
    assert_eq!(WindowSize::KB32.bytes(), 1 << 15);
    assert_eq!(WindowSize::MB2.bytes(), 1 << 21);
}
