//! Shared helpers for integration tests: build in-memory ustar archives and drain entries.
//!
//! Each test binary that declares `mod common;` compiles this independently and may use only a
//! subset of the helpers, so unused-code warnings are expected and allowed here.
#![allow(dead_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use arca_core::{Entry, EntryData};

/// Writes a numeric field as `width - 1` zero-padded octal digits followed by a NUL.
pub(crate) fn put_octal(hdr: &mut [u8; 512], start: usize, width: usize, val: u64) {
    let digits = format!("{val:0w$o}", w = width - 1);
    hdr[start..start + width - 1].copy_from_slice(digits.as_bytes());
    hdr[start + width - 1] = 0;
}

/// Builds a single ustar entry (header + data + block padding).
pub(crate) fn ustar(name: &str, typeflag: u8, data: &[u8]) -> Vec<u8> {
    let mut h = [0u8; 512];
    let nb = name.as_bytes();
    h[..nb.len()].copy_from_slice(nb);
    put_octal(&mut h, 100, 8, 0o644); // mode
    put_octal(&mut h, 124, 12, data.len() as u64); // size
    h[156] = typeflag;
    h[257..262].copy_from_slice(b"ustar");
    h[263] = b'0';
    h[264] = b'0';

    // Checksum: blank the field, sum unsigned, then write 6 octal digits + NUL + space.
    for b in &mut h[148..156] {
        *b = b' ';
    }
    let sum: u64 = h.iter().map(|&b| u64::from(b)).sum();
    h[148..154].copy_from_slice(format!("{sum:06o}").as_bytes());
    h[154] = 0;
    h[155] = b' ';

    let mut out = h.to_vec();
    out.extend_from_slice(data);
    let pad = (512 - data.len() % 512) % 512;
    out.resize(out.len() + pad, 0);
    out
}

/// Two zero blocks marking the end of an archive.
pub(crate) fn trailer() -> Vec<u8> {
    vec![0u8; 1024]
}

/// Reads an entry body to completion using a small buffer (exercises chunked reads).
pub(crate) fn drain<D: EntryData>(entry: &mut Entry<'_, D>) -> Vec<u8> {
    let mut out = Vec::new();
    let mut tmp = [0u8; 9];
    loop {
        let n = entry.data().read_chunk(&mut tmp).unwrap();
        if n == 0 {
            break;
        }
        out.extend_from_slice(&tmp[..n]);
    }
    out
}
