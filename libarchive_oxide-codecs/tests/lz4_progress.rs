// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Caller-driven progress regressions for the portable LZ4 frame decoder.

#![allow(clippy::unwrap_used)]
#![cfg(feature = "lz4")]

use libarchive_oxide_codecs::lz4::{Lz4Decoder, encode_frame};
use libarchive_oxide_core::{Codec, CodecStatus, EndOfInput, ErrorKind};

#[test]
fn whole_frame_crosses_header_and_block_states_in_one_call() {
    let payload = b"one supplied slice must remain usable across state transitions";
    let encoded = encode_frame(payload).unwrap();
    let mut decoder = Lz4Decoder::new();
    let mut output = [0_u8; 128];

    let step = decoder
        .process(&encoded, &mut output, EndOfInput::End)
        .unwrap()
        .validate(encoded.len(), output.len())
        .unwrap();

    assert_eq!(step.consumed, encoded.len());
    assert_eq!(step.produced, payload.len());
    assert_eq!(step.status, CodecStatus::Done);
    assert_eq!(&output[..step.produced], payload);
}

#[test]
fn concatenated_frames_cross_all_states_in_one_call() {
    let first = b"first member";
    let second = b"second member";
    let mut encoded = encode_frame(first).unwrap();
    encoded.extend_from_slice(&encode_frame(second).unwrap());
    let mut decoder = Lz4Decoder::new();
    let mut output = [0_u8; 128];

    let step = decoder
        .process(&encoded, &mut output, EndOfInput::End)
        .unwrap()
        .validate(encoded.len(), output.len())
        .unwrap();

    assert_eq!(step.consumed, encoded.len());
    assert_eq!(step.produced, first.len() + second.len());
    assert_eq!(step.status, CodecStatus::Done);
    assert_eq!(
        &output[..step.produced],
        [first.as_slice(), second].concat()
    );
}

#[test]
fn complete_frame_with_more_consumes_the_supplied_slice() {
    let payload = b"the source has not reported EOF yet";
    let encoded = encode_frame(payload).unwrap();
    let mut decoder = Lz4Decoder::new();
    let mut output = [0_u8; 128];

    let step = decoder
        .process(&encoded, &mut output, EndOfInput::More)
        .unwrap()
        .validate(encoded.len(), output.len())
        .unwrap();

    assert_eq!(step.consumed, encoded.len());
    assert_eq!(step.produced, payload.len());
    assert_eq!(step.status, CodecStatus::NeedInput);
    assert_eq!(&output[..step.produced], payload);

    let done = decoder
        .process(&[], &mut output, EndOfInput::End)
        .unwrap()
        .validate(0, output.len())
        .unwrap();
    assert_eq!(done.status, CodecStatus::Done);
}

#[test]
fn tiny_output_preserves_input_and_decoded_blocks() {
    let mut state = 0x9e37_79b9_u32;
    let payload = (0..160_000)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state.to_le_bytes()[0]
        })
        .collect::<Vec<_>>();
    let encoded = encode_frame(&payload).unwrap();
    assert!(encoded.len() > 2 * 64 * 1024);

    let mut decoder = Lz4Decoder::new();
    let mut reconstructed = Vec::new();
    let mut input_offset = 0;
    let mut output = [0_u8; 37];
    let mut done = false;

    for _ in 0..20_000 {
        let remaining = encoded.len() - input_offset;
        let step = decoder
            .process(&encoded[input_offset..], &mut output, EndOfInput::End)
            .unwrap()
            .validate(remaining, output.len())
            .unwrap();
        if step.status == CodecStatus::NeedInput {
            assert_eq!(
                step.consumed, remaining,
                "NeedInput may only follow full consumption of the supplied slice"
            );
        }
        input_offset += step.consumed;
        reconstructed.extend_from_slice(&output[..step.produced]);
        if step.status == CodecStatus::Done {
            done = true;
            break;
        }
        assert_ne!(
            (step.consumed, step.produced),
            (0, 0),
            "bounded decoder must make progress"
        );
    }

    assert!(done, "decoder exceeded the bounded iteration budget");
    assert_eq!(input_offset, encoded.len());
    assert_eq!(reconstructed, payload);
}

#[test]
fn split_headers_resume_with_the_remaining_frame_in_one_slice() {
    let payload = b"header boundary";
    let encoded = encode_frame(payload).unwrap();

    for split in [6, 7, 14, 15] {
        let mut decoder = Lz4Decoder::new();
        let mut output = [0_u8; 64];
        let first = decoder
            .process(&encoded[..split], &mut output, EndOfInput::More)
            .unwrap()
            .validate(split, output.len())
            .unwrap();
        assert_eq!(first.consumed, split);
        assert_eq!(first.produced, 0);
        assert_eq!(first.status, CodecStatus::NeedInput);

        let second = decoder
            .process(&encoded[split..], &mut output, EndOfInput::End)
            .unwrap()
            .validate(encoded.len() - split, output.len())
            .unwrap();
        assert_eq!(second.consumed, encoded.len() - split);
        assert_eq!(second.produced, payload.len());
        assert_eq!(second.status, CodecStatus::Done);
        assert_eq!(&output[..second.produced], payload);
    }
}

#[test]
fn truncated_second_frame_and_trailing_data_are_rejected() {
    let first = encode_frame(b"complete first member").unwrap();
    let second = encode_frame(b"truncated second member").unwrap();

    for suffix in [&second[..6], &[0xa5][..]] {
        let mut encoded = first.clone();
        encoded.extend_from_slice(suffix);
        let mut decoder = Lz4Decoder::new();
        let mut output = [0_u8; 128];
        let error = decoder
            .process(&encoded, &mut output, EndOfInput::End)
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Malformed);
    }
}
