// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Resource-limit regressions for portable frame decoders.

#![allow(clippy::unwrap_used)]
#![cfg(all(feature = "lz4", feature = "zstd"))]

use libarchive_oxide_codecs::{lz4, zstd};
use libarchive_oxide_core::{Codec, CodecStatus, EndOfInput, ErrorKind, Limits};

#[test]
fn zstd_rejects_declared_workspace_before_output() {
    let encoded = zstd::encode_frame(b"bounded Zstandard payload", Limits::safe()).unwrap();
    let limits = Limits::safe().with_codec_memory(Some(1024));
    let mut decoder = zstd::ZstdDecoder::with_limits(limits);
    let mut output = [0xa5; 64];
    let error = decoder
        .process(&encoded, &mut output, EndOfInput::More)
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Limit);
    assert_eq!(output, [0xa5; 64]);
}

#[test]
fn lz4_rejects_declared_workspace_before_output() {
    let encoded = lz4::encode_frame(b"bounded LZ4 payload").unwrap();
    let limits = Limits::safe().with_codec_memory(Some(1024));
    let mut decoder = lz4::Lz4Decoder::with_limits(limits);
    let mut output = [0xa5; 64];
    let error = decoder
        .process(&encoded, &mut output, EndOfInput::More)
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Limit);
    assert_eq!(output, [0xa5; 64]);
}

#[test]
fn zstd_end_marker_survives_bounded_partial_input_consumption() {
    let plain = (0_u8..=251).cycle().take(512 * 1024).collect::<Vec<_>>();
    let encoded = zstd::encode_frame(&plain, Limits::safe()).unwrap();
    let mut codec = zstd::ZstdDecoder::with_limits(Limits::safe());
    let mut reconstructed = Vec::new();
    let mut input_offset = 0;
    let mut output = [0_u8; 37];

    loop {
        let step = codec
            .process(&encoded[input_offset..], &mut output, EndOfInput::End)
            .unwrap()
            .validate(encoded.len() - input_offset, output.len())
            .unwrap();
        input_offset += step.consumed;
        reconstructed.extend_from_slice(&output[..step.produced]);
        if step.status == CodecStatus::Done {
            break;
        }
        assert_ne!(
            (step.consumed, step.produced),
            (0, 0),
            "bounded decoder must make progress"
        );
    }

    assert_eq!(input_offset, encoded.len());
    assert_eq!(reconstructed, plain);
}
