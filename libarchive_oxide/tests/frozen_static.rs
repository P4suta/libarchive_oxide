// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Compile-time checks for std-side dispatch types.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
// These matches enforce exhaustiveness and common result types.
#![allow(clippy::no_effect_underscore_binding, clippy::match_same_arms)]

use libarchive_oxide::extract::{AnyEntryData, AnyReader};
use libarchive_oxide::filter::{decoder, encoder, AnyDecoder, AnyEncoder};
use libarchive_oxide_core::filter::FilterId;
use libarchive_oxide_core::{EntryData, EntryReader, Transform};

/// Requires `EntryReader`.
fn assert_is_reader<R: EntryReader>() {}
/// Requires `EntryData`.
fn assert_is_entry_data<D: EntryData>() {}
/// Requires `Transform`.
fn assert_is_transform<T: Transform>() {}

#[test]
fn any_reader_is_entry_reader_without_erasure() {
    assert_is_reader::<AnyReader<'_>>();
    assert_is_entry_data::<AnyEntryData<'_>>();
}

#[test]
fn any_decoder_and_encoder_are_transforms() {
    assert_is_transform::<AnyDecoder>();
    assert_is_transform::<AnyEncoder>();
}

#[test]
fn decoder_is_origin_opaque() {
    // The hand-written gzip decoder and the reused zstd adapter are returned as ONE nominal type,
    // so a caller cannot tell hand-written from reused. The array below only type-checks because of
    // that single-type guarantee.
    let handwritten = decoder(FilterId::Gzip).expect("gzip built in");
    let reused = decoder(FilterId::Zstd).expect("zstd built in");
    let _same_type: [AnyDecoder; 2] = [handwritten, reused];

    let enc_hand = encoder(FilterId::Gzip).expect("gzip built in");
    let enc_reused = encoder(FilterId::Lz4).expect("lz4 built in");
    let _same_type: [AnyEncoder; 2] = [enc_hand, enc_reused];
}

/// Exhaustiveness guard for the std payload enum: adding a variant to [`AnyEntryData`] without
/// handling it here breaks the build, mechanically forcing the sealed enum to stay fully handled.
fn _exhaustive_entry_data(d: &AnyEntryData<'_>) {
    match d {
        AnyEntryData::Core(_) => {},
        AnyEntryData::Owned(_) => {},
    }
}

/// Exhaustiveness guard for the decoder enum (dual, filter axis).
fn _exhaustive_decoder(d: &AnyDecoder) {
    match d {
        AnyDecoder::Gzip(_) => {},
        AnyDecoder::Zstd(_) => {},
        AnyDecoder::Xz(_) => {},
        AnyDecoder::Lz4(_) => {},
    }
}

#[test]
fn exhaustiveness_guards_are_wired() {
    // Reference the guards so they are compiled (and thus enforce their matches) without dead-code.
    let _ = _exhaustive_entry_data as fn(&AnyEntryData<'_>);
    let _ = _exhaustive_decoder as fn(&AnyDecoder);
}
