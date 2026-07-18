//! Static (compile-time) proofs of the frozen abstraction on the std side.
//!
//! There is **no runtime type erasure** anywhere in the pipeline: the sealed [`AnyReader`] is an
//! [`EntryReader`] with an associated [`EntryData`]; `decoder()`/`encoder()` are origin-opaque (the
//! hand-written gzip codec and the reused adapters share one nominal type); and [`AnyDecoder`]/
//! [`AnyEncoder`] are [`Transform`]s (the filter-axis dual). These bounds only type-check because
//! the abstraction is shaped exactly as frozen — that is the point of the file.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
// The match/binding constructs below exist purely to force compile-time exhaustiveness and
// single-type checks; their "no effect" and "identical arms" are the whole point.
#![allow(clippy::no_effect_underscore_binding, clippy::match_same_arms)]

use libarchive_oxide::extract::{AnyEntryData, AnyReader};
use libarchive_oxide_core::filter::FilterId;
use libarchive_oxide_core::{EntryData, EntryReader, Transform};
use libarchive_oxide::filter::{decoder, encoder, AnyDecoder, AnyEncoder};

/// The sealed std reader satisfies `EntryReader` — statically, no `dyn`.
fn assert_is_reader<R: EntryReader>() {}
/// Its payload cursor satisfies `EntryData`.
fn assert_is_entry_data<D: EntryData>() {}
/// The filter-axis dual: any decoder/encoder is a `Transform`.
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
        AnyEntryData::Core(_) => {}
        AnyEntryData::Owned(_) => {}
    }
}

/// Exhaustiveness guard for the decoder enum (dual, filter axis).
fn _exhaustive_decoder(d: &AnyDecoder) {
    match d {
        AnyDecoder::Gzip(_) => {}
        AnyDecoder::Zstd(_) => {}
        AnyDecoder::Xz(_) => {}
        AnyDecoder::Lz4(_) => {}
    }
}

#[test]
fn exhaustiveness_guards_are_wired() {
    // Reference the guards so they are compiled (and thus enforce their matches) without dead-code.
    let _ = _exhaustive_entry_data as fn(&AnyEntryData<'_>);
    let _ = _exhaustive_decoder as fn(&AnyDecoder);
}
