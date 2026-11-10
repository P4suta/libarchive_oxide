// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! RFC 4648 Base64 incremental codec, canonical padding, and limit contracts.

#![allow(clippy::expect_used, clippy::panic)]

use libarchive_oxide_codecs::base64::{Base64Decoder, Base64Encoder};
use libarchive_oxide_protocol::{Codec, CodecStatus, EndOfInput, ErrorKind, Limits};

fn drive(
    mut codec: impl Codec,
    input: &[u8],
    input_chunk: usize,
    output_chunk: usize,
) -> Result<Vec<u8>, libarchive_oxide_protocol::ArchiveError> {
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
        let step = codec
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
fn rfc4648_vectors_round_trip_at_every_small_chunk_boundary() {
    for (plain, encoded) in [
        (b"".as_slice(), b"".as_slice()),
        (b"f", b"Zg=="),
        (b"fo", b"Zm8="),
        (b"foo", b"Zm9v"),
        (b"foob", b"Zm9vYg=="),
        (b"fooba", b"Zm9vYmE="),
        (b"foobar", b"Zm9vYmFy"),
    ] {
        for input_chunk in 1..=encoded.len().max(1) {
            for output_chunk in 1..=3 {
                assert_eq!(
                    drive(
                        Base64Decoder::new(Limits::safe()),
                        encoded,
                        input_chunk,
                        output_chunk,
                    )
                    .expect("decode RFC vector"),
                    plain
                );
            }
        }
        for input_chunk in 1..=plain.len().max(1) {
            for output_chunk in 1..=4 {
                assert_eq!(
                    drive(
                        Base64Encoder::new(Limits::safe()),
                        plain,
                        input_chunk,
                        output_chunk,
                    )
                    .expect("encode RFC vector"),
                    encoded
                );
            }
        }
    }
}

#[test]
fn decoder_accepts_ascii_whitespace_but_rejects_noncanonical_or_truncated_input() {
    assert_eq!(
        drive(
            Base64Decoder::new(Limits::safe()),
            b" Zm9v\r\nYmFy\t ",
            1,
            1,
        )
        .expect("decode whitespace"),
        b"foobar"
    );

    for malformed in [
        b"A".as_slice(),
        b"AAA",
        b"=AAA",
        b"A===",
        b"TQ=A",
        b"TQ==x",
        b"Zh==",
        b"Zm9=",
        b"Zm$v",
    ] {
        let error = drive(Base64Decoder::new(Limits::safe()), malformed, 1, 2)
            .expect_err("malformed Base64 must fail");
        assert_eq!(error.kind(), ErrorKind::Malformed, "{malformed:?}");
    }
}

#[test]
fn decoder_and_encoder_enforce_the_plaintext_total_limit() {
    let limits = Limits::safe().with_decoded_total(Some(2));
    assert_eq!(
        drive(Base64Decoder::new(limits), b"Zm9v", 4, 3)
            .expect_err("decoded bomb")
            .kind(),
        ErrorKind::Limit
    );
    assert_eq!(
        drive(Base64Encoder::new(limits), b"foo", 3, 4)
            .expect_err("encoder plaintext limit")
            .kind(),
        ErrorKind::Limit
    );
}
