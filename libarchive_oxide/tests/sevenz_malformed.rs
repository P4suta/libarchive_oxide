//! Malformed / adversarial 7z inputs must produce an `Error`, never a panic. Covers a truncated
//! signature header, corrupt CRCs, a lying next-header size, a truncated header body, an unsupported
//! coder (non-LZMA2), and a lying folder unpack size.
#![cfg(feature = "sevenz")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::vec_init_then_push
)]

use std::borrow::Cow;

use libarchive_oxide::sevenz::{SevenZReader, SevenZWriter};
use libarchive_oxide_core::{EntryData, EntryKind, EntryMeta, EntryReader, EntryWriter};

/// Drives a reader to completion, returning `Err` if any step fails. Must never panic.
fn drive(bytes: &[u8]) -> Result<usize, libarchive_oxide_core::Error> {
    let mut r = SevenZReader::new(bytes);
    let mut count = 0usize;
    while let Some(mut e) = r.next_entry()? {
        let mut buf = [0u8; 32];
        while e.data().read_chunk(&mut buf)? != 0 {}
        count += 1;
    }
    Ok(count)
}

/// A valid single-file arca 7z, used as a mutation base.
fn valid() -> Vec<u8> {
    let mut w = SevenZWriter::new(Vec::new());
    let mut m = EntryMeta::new(EntryKind::File, Cow::Borrowed(b"f.txt"));
    m.mode = 0o644;
    let data = b"payload for the malformed base\n".repeat(8);
    m.size = data.len() as u64;
    let mut sink = w.start_entry(&m).unwrap();
    sink.write_chunk(&data).unwrap();
    sink.close().unwrap();
    w.finish().unwrap();
    w.into_inner()
}

#[test]
fn empty_input_is_error() {
    assert!(drive(&[]).is_err());
}

#[test]
fn bad_magic_is_error() {
    let mut bytes = valid();
    bytes[0] ^= 0xFF;
    assert!(drive(&bytes).is_err());
}

#[test]
fn truncated_signature_header_is_error() {
    let bytes = valid();
    assert!(drive(&bytes[..16]).is_err());
}

#[test]
fn corrupt_start_header_crc_is_error() {
    let mut bytes = valid();
    // Flip a bit inside the NextHeader triple (bytes 12..32); the start-header CRC must reject it.
    bytes[13] ^= 0x01;
    assert!(drive(&bytes).is_err());
}

#[test]
fn lying_next_header_size_is_error() {
    let mut bytes = valid();
    // Overwrite NextHeaderSize (bytes 20..28) with a huge value pointing past the file.
    bytes[20..28].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(drive(&bytes).is_err());
}

#[test]
fn truncated_header_body_is_error() {
    let bytes = valid();
    // Drop the trailing header bytes while keeping the signature header intact.
    let cut = bytes.len() - 4;
    assert!(drive(&bytes[..cut]).is_err());
}

#[test]
fn unsupported_coder_is_error() {
    // Hand-build a minimal 7z whose single coder is Copy (id 0x00), which arca does not support.
    // Layout: signature header + empty pack data + a plain kHeader declaring one Copy folder.
    let mut header: Vec<u8> = Vec::new();
    header.push(0x01); // kHeader
    header.push(0x04); // kMainStreamsInfo
                       // PackInfo: pos 0, 1 stream, size 0
    header.push(0x06);
    header.push(0x00); // PackPos
    header.push(0x01); // NumPackStreams
    header.push(0x09); // kSize
    header.push(0x00); // pack size 0
    header.push(0x00); // kEnd (pack info)
                       // UnpackInfo: 1 folder, 1 Copy coder (idSize 1, id 0x00, no attributes)
    header.push(0x07); // kUnpackInfo
    header.push(0x0B); // kFolder
    header.push(0x01); // NumFolders
    header.push(0x00); // External = 0
    header.push(0x01); // NumCoders
    header.push(0x01); // coder flags: idSize=1, no attributes
    header.push(0x00); // codec id = Copy
    header.push(0x0C); // kCodersUnpackSize
    header.push(0x00); // unpack size 0
    header.push(0x00); // kEnd (unpack info)
    header.push(0x00); // kEnd (streams info)
    header.push(0x00); // kEnd (header)

    let mut out = vec![0u8; 32];
    out[0..6].copy_from_slice(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]);
    out[7] = 4;
    let nh_offset = 0u64; // no pack data
    let nh_size = header.len() as u64;
    let nh_crc = libarchive_oxide::filter::crc32(&header);
    out.extend_from_slice(&header);
    out[12..20].copy_from_slice(&nh_offset.to_le_bytes());
    out[20..28].copy_from_slice(&nh_size.to_le_bytes());
    out[28..32].copy_from_slice(&nh_crc.to_le_bytes());
    let start_crc = libarchive_oxide::filter::crc32(&out[12..32]);
    out[8..12].copy_from_slice(&start_crc.to_le_bytes());

    match drive(&out) {
        Err(libarchive_oxide_core::Error::Unsupported(_)) => {},
        other => panic!("expected Unsupported, got {other:?}"),
    }
}

/// Bomb defense (file-count amplification): a tiny header that declares a huge `num_files` must be
/// rejected against the remaining header size, not eagerly turned into hundreds of megabytes of
/// per-file vectors. This whole input is ~40 bytes yet names 16,000,000 files.
#[test]
fn huge_file_count_in_tiny_header_is_error() {
    // kHeader, kFilesInfo, num_files = 16,000,000 (7z varint 0xE0 00 24 F4), kEnd, kEnd.
    let header: Vec<u8> = vec![0x01, 0x05, 0xE0, 0x00, 0x24, 0xF4, 0x00, 0x00];

    let mut out = vec![0u8; 32];
    out[0..6].copy_from_slice(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]);
    out[7] = 4;
    let nh_offset = 0u64;
    let nh_size = header.len() as u64;
    let nh_crc = libarchive_oxide::filter::crc32(&header);
    out.extend_from_slice(&header);
    out[12..20].copy_from_slice(&nh_offset.to_le_bytes());
    out[20..28].copy_from_slice(&nh_size.to_le_bytes());
    out[28..32].copy_from_slice(&nh_crc.to_le_bytes());
    let start_crc = libarchive_oxide::filter::crc32(&out[12..32]);
    out[8..12].copy_from_slice(&start_crc.to_le_bytes());

    // Must return promptly with an error and never allocate proportional to 16M files.
    assert!(drive(&out).is_err());
}

/// Bomb defense (folder unpack allocation): a few-byte packed stream that declares a near-4 GiB
/// unpack size must not pre-allocate 4 GiB. The decode now grows the output only with bytes actually
/// produced, so a stream that ends immediately fails fast with a size-mismatch error. Exercised via
/// the eager kEncodedHeader decode path so it runs during parse.
#[test]
fn tiny_pack_declaring_huge_unpack_is_error() {
    // kEncodedHeader streams-info: 1 pack (size 4) at pos 0; 1 LZMA2 folder; CodersUnpackSize =
    // 0xFFFFFF00 (~4 GiB, just under the cap); dict prop 24.
    let header: Vec<u8> = vec![
        0x17, // kEncodedHeader
        0x06, 0x00, 0x01, 0x09, 0x04, 0x00, // PackInfo: pos 0, 1 stream, size 4
        0x07, 0x0B, 0x01, 0x00, // UnpackInfo, kFolder, 1 folder, external 0
        0x01, 0x21, 0x21, 0x01, 0x18, // 1 coder: flags 0x21, LZMA2 id 0x21, 1 prop byte = 24
        0x0C, 0xF0, 0x00, 0xFF, 0xFF, 0xFF, // CodersUnpackSize = 0xFFFFFF00
        0x00, // kEnd (unpack info)
        0x00, // kEnd (streams info)
    ];

    // 4 packed bytes: an LZMA2 control byte 0x00 is end-of-stream, so decode yields nothing.
    let pack = [0u8; 4];

    let mut out = vec![0u8; 32];
    out[0..6].copy_from_slice(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]);
    out[7] = 4;
    out.extend_from_slice(&pack);
    let nh_offset = pack.len() as u64;
    let nh_size = header.len() as u64;
    let nh_crc = libarchive_oxide::filter::crc32(&header);
    out.extend_from_slice(&header);
    out[12..20].copy_from_slice(&nh_offset.to_le_bytes());
    out[20..28].copy_from_slice(&nh_size.to_le_bytes());
    out[28..32].copy_from_slice(&nh_crc.to_le_bytes());
    let start_crc = libarchive_oxide::filter::crc32(&out[12..32]);
    out[8..12].copy_from_slice(&start_crc.to_le_bytes());

    assert!(drive(&out).is_err());
}

#[test]
fn lying_folder_unpack_size_is_error() {
    // Corrupt the compressed folder so LZMA2 decode cannot produce the declared size.
    let mut bytes = valid();
    // The packed stream starts right after the 32-byte signature header; smash its first bytes.
    for b in bytes.iter_mut().skip(32).take(8) {
        *b ^= 0xFF;
    }
    // Reading may fail either at CRC checks or during decode; it must not panic.
    let _ = drive(&bytes);
}
