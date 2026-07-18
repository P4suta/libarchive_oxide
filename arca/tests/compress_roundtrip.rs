//! Encode/decode duality: for every codec, `decompress ∘ compress = id`, plus a cross-check that
//! our gzip output is readable by an independent decoder (flate2).

mod common;

use std::io::Read;

use arca::{compress, decompress};
use arca_core::filter::FilterId;
use common::{trailer, ustar};

fn sample_tar() -> Vec<u8> {
    let mut tar = Vec::new();
    tar.extend(ustar("readme.txt", b'0', b"arca compress round-trip\n"));
    tar.extend(ustar("dir/", b'5', b""));
    let payload: Vec<u8> = (0..30_000u32).map(|i| (i % 251) as u8).collect();
    tar.extend(ustar("blob.bin", b'0', &payload));
    tar.extend(trailer());
    tar
}

#[test]
fn compress_then_decompress_round_trips_every_codec() {
    let tar = sample_tar();
    for id in [FilterId::Gzip, FilterId::Zstd, FilterId::Xz, FilterId::Lz4] {
        let compressed = compress(&tar, id).unwrap();
        assert_ne!(compressed, tar, "{id:?} should transform the bytes");
        let plain = decompress(&compressed).unwrap();
        assert_eq!(plain.as_ref(), tar.as_slice(), "round-trip for {id:?}");
    }
}

#[test]
fn gzip_output_is_independently_decodable() {
    let data = b"cross-impl check of arca's gzip framing and CRC32 ".repeat(200);
    let compressed = compress(&data, FilterId::Gzip).unwrap();
    assert_eq!(&compressed[..2], &[0x1f, 0x8b]);

    let mut decoder = flate2::read::GzDecoder::new(&compressed[..]);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out).unwrap();
    assert_eq!(out, data);
}
