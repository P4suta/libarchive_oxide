//! Regression test for a gzip header that spans multiple `step` feeds.
//!
//! The whole-slice caller always hands the header over at once, but the incremental source pipeline
//! feeds bytes in tiny pushes. [`GzipDecoder`] must accumulate the RFC 1952 header (including a
//! variable-length FNAME) across `step` calls and still decode to the identical plaintext.
#![cfg(feature = "gzip")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use libarchive_oxide_core::transform::{Status, Transform};
use libarchive_oxide::filter::gzip::GzipDecoder;
use libarchive_oxide::filter::{crc32, deflate};

/// A gzip frame carrying an FNAME field, so the header is 19 bytes (10 fixed + "name.txt\0").
fn gzip_with_fname(plain: &[u8]) -> Vec<u8> {
    let mut gz = vec![0x1f, 0x8b, 0x08, 0x08, 0, 0, 0, 0, 0x00, 0xff];
    gz.extend_from_slice(b"name.txt\0");
    gz.extend_from_slice(&deflate(plain));
    gz.extend_from_slice(&crc32(plain).to_le_bytes());
    let isize_field = u32::try_from(plain.len() & 0xFFFF_FFFF).unwrap();
    gz.extend_from_slice(&isize_field.to_le_bytes());
    gz
}

/// Drive `GzipDecoder` feeding `gz` `chunk` bytes at a time, topping up input only when a step makes
/// no progress (the truly incremental protocol).
fn decode_chunked(gz: &[u8], chunk: usize) -> Vec<u8> {
    let mut dec = GzipDecoder::new();
    let mut out = Vec::new();
    let mut obuf = [0u8; 64];
    let mut pending: Vec<u8> = Vec::new();
    let mut pos = 0usize;

    loop {
        let step = dec.step(&pending, &mut obuf).unwrap();
        out.extend_from_slice(&obuf[..step.produced]);
        pending.drain(..step.consumed);
        if step.status == Status::Done {
            break;
        }
        let progressed = step.consumed != 0 || step.produced != 0;
        if !progressed {
            if pos < gz.len() {
                let end = (pos + chunk).min(gz.len());
                pending.extend_from_slice(&gz[pos..end]);
                pos = end;
            } else {
                // Input exhausted: drain any tail via finish.
                loop {
                    let s = dec.finish(&mut obuf).unwrap();
                    out.extend_from_slice(&obuf[..s.produced]);
                    if s.status == Status::Done || s.produced == 0 {
                        break;
                    }
                }
                break;
            }
        }
    }
    out
}

#[test]
fn header_split_one_byte_at_a_time() {
    let plain = b"the quick brown fox jumps over the lazy dog, incrementally\n";
    let gz = gzip_with_fname(plain);
    assert_eq!(decode_chunked(&gz, 1), plain);
}

#[test]
fn header_split_matches_whole_slice_various_chunks() {
    let plain: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
    let gz = gzip_with_fname(&plain);
    let whole = decode_chunked(&gz, gz.len());
    assert_eq!(whole, plain);
    for chunk in [1usize, 2, 3, 5, 9, 17, 19, 64, 100] {
        assert_eq!(decode_chunked(&gz, chunk), plain, "chunk {chunk}");
    }
}

#[test]
fn plain_ten_byte_header_still_splits() {
    // Even a minimal (no-flags) 10-byte header must survive one-byte feeding.
    let plain = b"no fname header here";
    let mut gz = vec![0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0x00, 0xff];
    gz.extend_from_slice(&deflate(plain));
    gz.extend_from_slice(&crc32(plain).to_le_bytes());
    gz.extend_from_slice(&u32::try_from(plain.len()).unwrap().to_le_bytes());
    assert_eq!(decode_chunked(&gz, 1), plain);
}
