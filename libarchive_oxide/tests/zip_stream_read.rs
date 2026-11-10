// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Forward-only ZIP reader contracts.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::io::{Cursor, Read, Write};
#[cfg(feature = "aes")]
use std::sync::Arc;

#[cfg(feature = "aes")]
use libarchive_oxide::{AesStrength, OpenOptions, PasswordCandidates, SecretBytes};
use libarchive_oxide::{
    ArchiveMetadata, ArchivePath, ArchiveReader, ArchiveWriter, EntryKind, EntryMetadata,
    ErrorKind, FormatId, Limits, ReaderEvent, ZipMethod,
};
use zip::write::{SimpleFileOptions, ZipWriter};

type CollectedEntries = Vec<(Vec<u8>, Vec<u8>)>;

#[cfg(feature = "async")]
use std::pin::Pin;
#[cfg(feature = "async")]
use std::task::{Context, Poll};

#[cfg(feature = "async")]
use futures_io::AsyncRead;
#[cfg(feature = "async")]
use libarchive_oxide::AsyncArchiveReader;

#[derive(Debug)]
struct OneByte {
    bytes: Vec<u8>,
    position: usize,
}

impl OneByte {
    fn new(bytes: Vec<u8>) -> Self {
        Self { bytes, position: 0 }
    }
}

impl Read for OneByte {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        if output.is_empty() || self.position == self.bytes.len() {
            return Ok(0);
        }
        output[0] = self.bytes[self.position];
        self.position += 1;
        Ok(1)
    }
}

#[cfg(feature = "async")]
#[derive(Debug)]
struct AsyncOneByte {
    bytes: Vec<u8>,
    position: usize,
}

#[cfg(feature = "async")]
impl AsyncRead for AsyncOneByte {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        if output.is_empty() || self.position == self.bytes.len() {
            return Poll::Ready(Ok(0));
        }
        output[0] = self.bytes[self.position];
        self.position += 1;
        Poll::Ready(Ok(1))
    }
}

fn streaming_zip(method: ZipMethod, entries: &[(&[u8], &[u8])]) -> Vec<u8> {
    streaming_zip_with_size_mode(method, entries, true)
}

fn streaming_zip_with_size_mode(
    method: ZipMethod,
    entries: &[(&[u8], &[u8])],
    declare_size: bool,
) -> Vec<u8> {
    let mut writer = ArchiveWriter::with_zip_method(Vec::new(), method, Limits::default());
    for (path, body) in entries {
        let metadata =
            EntryMetadata::builder(EntryKind::File, ArchivePath::from_bytes((*path).to_vec()))
                .size(declare_size.then_some(body.len() as u64))
                .build();
        writer.start_entry(&metadata).expect("start ZIP entry");
        writer.write_data(body).expect("write ZIP entry");
        writer.end_entry().expect("end ZIP entry");
    }
    writer.finish().expect("finish ZIP archive")
}

fn independent_zip(method: zip::CompressionMethod, path: &str, body: &[u8]) -> Vec<u8> {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    writer
        .start_file(
            path,
            SimpleFileOptions::default().compression_method(method),
        )
        .expect("start independent ZIP member");
    writer
        .write_all(body)
        .expect("write independent ZIP member");
    writer
        .finish()
        .expect("finish independent ZIP")
        .into_inner()
}

fn find_signature(bytes: &[u8], signature: u32) -> usize {
    let signature = signature.to_le_bytes();
    bytes
        .windows(4)
        .position(|window| window == signature)
        .expect("ZIP signature")
}

#[cfg(feature = "aes")]
fn zipcrypto_update(keys: &mut [u32; 3], plaintext: u8) {
    fn crc32_byte(mut crc: u32, byte: u8) -> u32 {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & (crc & 1).wrapping_neg());
        }
        crc
    }

    keys[0] = crc32_byte(keys[0], plaintext);
    keys[1] = keys[1]
        .wrapping_add(keys[0] & 0xff)
        .wrapping_mul(0x0808_8405)
        .wrapping_add(1);
    keys[2] = crc32_byte(keys[2], keys[1].to_le_bytes()[3]);
}

#[cfg(feature = "aes")]
fn zipcrypto_stream_byte(keys: [u32; 3]) -> u8 {
    let key = keys[2].to_le_bytes();
    let value = u16::from_le_bytes([key[0], key[1]]) | 2;
    (value.wrapping_mul(value ^ 1) >> 8).to_le_bytes()[0]
}

#[cfg(all(feature = "aes", feature = "xz"))]
fn add_encrypted_xz_padding(mut archive: Vec<u8>, password: &[u8]) -> Vec<u8> {
    let name = usize::from(u16::from_le_bytes([archive[26], archive[27]]));
    let extra = usize::from(u16::from_le_bytes([archive[28], archive[29]]));
    let payload = 30 + name + extra;
    let central = find_signature(&archive, 0x0201_4b50);
    let descriptor = central - 16;
    let mut keys = [0x1234_5678, 0x2345_6789, 0x3456_7890];
    for &byte in password {
        zipcrypto_update(&mut keys, byte);
    }
    for &ciphertext in &archive[payload..descriptor] {
        let plaintext = ciphertext ^ zipcrypto_stream_byte(keys);
        zipcrypto_update(&mut keys, plaintext);
    }
    let mut padding = [0_u8; 4];
    for byte in &mut padding {
        *byte ^= zipcrypto_stream_byte(keys);
        zipcrypto_update(&mut keys, 0);
    }
    archive.splice(descriptor..descriptor, padding);

    let descriptor = descriptor + 4;
    let descriptor_compressed =
        u32::from_le_bytes(archive[descriptor + 8..descriptor + 12].try_into().unwrap()) + 4;
    archive[descriptor + 8..descriptor + 12].copy_from_slice(&descriptor_compressed.to_le_bytes());
    let central = central + 4;
    let central_compressed =
        u32::from_le_bytes(archive[central + 20..central + 24].try_into().unwrap()) + 4;
    archive[central + 20..central + 24].copy_from_slice(&central_compressed.to_le_bytes());
    let eocd = find_signature(&archive[central..], 0x0605_4b50) + central;
    let central = u32::try_from(central).unwrap();
    archive[eocd + 16..eocd + 20].copy_from_slice(&central.to_le_bytes());
    archive
}

#[cfg(all(feature = "aes", feature = "xz"))]
fn add_aes_xz_padding(mut archive: Vec<u8>, password: &[u8]) -> Vec<u8> {
    use ctr::cipher::{KeyIvInit, StreamCipher};
    use hmac::Mac;
    use hmac::digest::KeyInit;
    use zeroize::Zeroize;

    let name = usize::from(u16::from_le_bytes(archive[26..28].try_into().unwrap()));
    let extra = usize::from(u16::from_le_bytes(archive[28..30].try_into().unwrap()));
    let payload = 30 + name + extra;
    let salt: [u8; 16] = archive[payload..payload + 16].try_into().unwrap();
    let ciphertext = payload + 18;
    let central = find_signature(&archive, 0x0201_4b50);
    let descriptor = central - 16;
    let authentication = descriptor - 10;

    let mut key_material = [0_u8; 66];
    pbkdf2::pbkdf2_hmac::<sha1::Sha1>(password, &salt, 1_000, &mut key_material);
    let mut counter = [0_u8; 16];
    counter[0] = 1;
    let mut cipher =
        ctr::Ctr128LE::<aes::Aes256>::new_from_slices(&key_material[..32], &counter).unwrap();
    let mut prior = archive[ciphertext..authentication].to_vec();
    cipher.apply_keystream(&mut prior);
    let mut padding = [0_u8; 4];
    cipher.apply_keystream(&mut padding);

    let mut mac =
        <hmac::Hmac<sha1::Sha1> as KeyInit>::new_from_slice(&key_material[32..64]).unwrap();
    mac.update(&archive[ciphertext..authentication]);
    mac.update(&padding);
    let digest = mac.finalize().into_bytes();
    key_material.zeroize();

    archive.splice(authentication..authentication, padding);
    let authentication = authentication + 4;
    archive[authentication..authentication + 10].copy_from_slice(&digest[..10]);
    let descriptor = descriptor + 4;
    let compressed =
        u32::from_le_bytes(archive[descriptor + 8..descriptor + 12].try_into().unwrap()) + 4;
    archive[descriptor + 8..descriptor + 12].copy_from_slice(&compressed.to_le_bytes());
    let central = central + 4;
    archive[central + 20..central + 24].copy_from_slice(&compressed.to_le_bytes());
    let eocd = find_signature(&archive[central..], 0x0605_4b50) + central;
    archive[eocd + 16..eocd + 20].copy_from_slice(&u32::try_from(central).unwrap().to_le_bytes());
    archive
}

#[cfg(feature = "gzip")]
fn stored_deflate64(data: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::new();
    if data.is_empty() {
        return vec![1, 0, 0, 0xff, 0xff];
    }
    let mut remaining = data;
    while !remaining.is_empty() {
        let count = remaining.len().min(usize::from(u16::MAX));
        encoded.push(u8::from(count == remaining.len()));
        let length = u16::try_from(count).unwrap();
        encoded.extend_from_slice(&length.to_le_bytes());
        encoded.extend_from_slice(&(!length).to_le_bytes());
        encoded.extend_from_slice(&remaining[..count]);
        remaining = &remaining[count..];
    }
    encoded
}

#[cfg(feature = "gzip")]
fn deflate64_zip(path: &[u8], body: &[u8]) -> Vec<u8> {
    let compressed = stored_deflate64(body);
    deflate64_zip_with_compressed(path, body, &compressed)
}

#[cfg(feature = "gzip")]
fn deflate64_zip_with_compressed(path: &[u8], body: &[u8], compressed: &[u8]) -> Vec<u8> {
    let compressed_size = u32::try_from(compressed.len()).unwrap();
    let body_size = u32::try_from(body.len()).unwrap();
    let name_size = u16::try_from(path.len()).unwrap();
    let checksum = libarchive_oxide::filter::crc32(body);
    let mut archive = Vec::new();
    archive.extend_from_slice(b"PK\x03\x04");
    for value in [21_u16, 0, 9, 0, 0] {
        archive.extend_from_slice(&value.to_le_bytes());
    }
    for value in [checksum, compressed_size, body_size] {
        archive.extend_from_slice(&value.to_le_bytes());
    }
    archive.extend_from_slice(&name_size.to_le_bytes());
    archive.extend_from_slice(&0_u16.to_le_bytes());
    archive.extend_from_slice(path);
    archive.extend_from_slice(compressed);

    let central_offset = u32::try_from(archive.len()).unwrap();
    archive.extend_from_slice(b"PK\x01\x02");
    for value in [0x031e_u16, 21, 0, 9, 0, 0] {
        archive.extend_from_slice(&value.to_le_bytes());
    }
    for value in [checksum, compressed_size, body_size] {
        archive.extend_from_slice(&value.to_le_bytes());
    }
    archive.extend_from_slice(&name_size.to_le_bytes());
    for value in [0_u16; 4] {
        archive.extend_from_slice(&value.to_le_bytes());
    }
    archive.extend_from_slice(&(0o100_644_u32 << 16).to_le_bytes());
    archive.extend_from_slice(&0_u32.to_le_bytes());
    archive.extend_from_slice(path);
    let central_size = u32::try_from(archive.len()).unwrap() - central_offset;

    archive.extend_from_slice(b"PK\x05\x06");
    for value in [0_u16, 0, 1, 1] {
        archive.extend_from_slice(&value.to_le_bytes());
    }
    archive.extend_from_slice(&central_size.to_le_bytes());
    archive.extend_from_slice(&central_offset.to_le_bytes());
    archive.extend_from_slice(&0_u16.to_le_bytes());
    archive
}

#[cfg(feature = "gzip")]
fn deflate64_descriptor_zip(path: &[u8], body: &[u8], signed: bool) -> Vec<u8> {
    with_deflate64_descriptor(deflate64_zip(path, body), signed)
}

#[cfg(feature = "gzip")]
fn with_deflate64_descriptor(mut archive: Vec<u8>, signed: bool) -> Vec<u8> {
    let central = find_signature(&archive, 0x0201_4b50);
    let checksum = u32::from_le_bytes(archive[central + 16..central + 20].try_into().unwrap());
    let compressed = u32::from_le_bytes(archive[central + 20..central + 24].try_into().unwrap());
    let uncompressed = u32::from_le_bytes(archive[central + 24..central + 28].try_into().unwrap());

    let local_flags = u16::from_le_bytes(archive[6..8].try_into().unwrap()) | 8;
    archive[6..8].copy_from_slice(&local_flags.to_le_bytes());
    archive[14..26].fill(0);
    let central_flags =
        u16::from_le_bytes(archive[central + 8..central + 10].try_into().unwrap()) | 8;
    archive[central + 8..central + 10].copy_from_slice(&central_flags.to_le_bytes());

    let mut descriptor = Vec::with_capacity(if signed { 16 } else { 12 });
    if signed {
        descriptor.extend_from_slice(b"PK\x07\x08");
    }
    for value in [checksum, compressed, uncompressed] {
        descriptor.extend_from_slice(&value.to_le_bytes());
    }
    let descriptor_len = descriptor.len();
    archive.splice(central..central, descriptor);
    let shifted_central = central + descriptor_len;
    let eocd = find_signature(&archive[shifted_central..], 0x0605_4b50) + shifted_central;
    archive[eocd + 16..eocd + 20]
        .copy_from_slice(&u32::try_from(shifted_central).unwrap().to_le_bytes());
    archive
}

#[cfg(feature = "gzip")]
fn deflate64_zip64_descriptor_zip(path: &[u8], body: &[u8], signed: bool) -> Vec<u8> {
    let mut archive = deflate64_zip(path, body);
    let central = find_signature(&archive, 0x0201_4b50);
    let checksum = u32::from_le_bytes(archive[central + 16..central + 20].try_into().unwrap());
    let compressed = u64::from(u32::from_le_bytes(
        archive[central + 20..central + 24].try_into().unwrap(),
    ));
    let uncompressed = u64::from(u32::from_le_bytes(
        archive[central + 24..central + 28].try_into().unwrap(),
    ));

    archive[4..6].copy_from_slice(&45_u16.to_le_bytes());
    let local_flags = u16::from_le_bytes(archive[6..8].try_into().unwrap()) | 8;
    archive[6..8].copy_from_slice(&local_flags.to_le_bytes());
    archive[14..18].fill(0);
    archive[18..26].fill(0xff);
    archive[central + 6..central + 8].copy_from_slice(&45_u16.to_le_bytes());
    let central_flags =
        u16::from_le_bytes(archive[central + 8..central + 10].try_into().unwrap()) | 8;
    archive[central + 8..central + 10].copy_from_slice(&central_flags.to_le_bytes());

    let mut descriptor = Vec::with_capacity(if signed { 24 } else { 20 });
    if signed {
        descriptor.extend_from_slice(b"PK\x07\x08");
    }
    descriptor.extend_from_slice(&checksum.to_le_bytes());
    descriptor.extend_from_slice(&compressed.to_le_bytes());
    descriptor.extend_from_slice(&uncompressed.to_le_bytes());
    let descriptor_len = descriptor.len();
    archive.splice(central..central, descriptor);
    let shifted_central = central + descriptor_len;
    let eocd = find_signature(&archive[shifted_central..], 0x0605_4b50) + shifted_central;
    archive[eocd + 16..eocd + 20]
        .copy_from_slice(&u32::try_from(shifted_central).unwrap().to_le_bytes());
    archive
}

#[cfg(feature = "gzip")]
fn official_wide_deflate64_member() -> (Vec<u8>, Vec<u8>) {
    let archive = include_bytes!("fixtures/zip/7zip/deflate64.zip");
    let eocd = archive
        .windows(4)
        .rposition(|window| window == b"PK\x05\x06")
        .unwrap();
    let mut central = usize::try_from(u32::from_le_bytes(
        archive[eocd + 16..eocd + 20].try_into().unwrap(),
    ))
    .unwrap();
    let (local, compressed_size) = loop {
        assert_eq!(&archive[central..central + 4], b"PK\x01\x02");
        let name_length = usize::from(u16::from_le_bytes(
            archive[central + 28..central + 30].try_into().unwrap(),
        ));
        let extra_length = usize::from(u16::from_le_bytes(
            archive[central + 30..central + 32].try_into().unwrap(),
        ));
        let comment_length = usize::from(u16::from_le_bytes(
            archive[central + 32..central + 34].try_into().unwrap(),
        ));
        if &archive[central + 46..central + 46 + name_length] == b"wide-window.bin" {
            break (
                usize::try_from(u32::from_le_bytes(
                    archive[central + 42..central + 46].try_into().unwrap(),
                ))
                .unwrap(),
                usize::try_from(u32::from_le_bytes(
                    archive[central + 20..central + 24].try_into().unwrap(),
                ))
                .unwrap(),
            );
        }
        central += 46 + name_length + extra_length + comment_length;
    };
    let name_length = usize::from(u16::from_le_bytes(
        archive[local + 26..local + 28].try_into().unwrap(),
    ));
    let extra_length = usize::from(u16::from_le_bytes(
        archive[local + 28..local + 30].try_into().unwrap(),
    ));
    let data = local + 30 + name_length + extra_length;

    let mut base = vec![0_u8; 50_000];
    let mut state = 0x1234_5678_u32;
    for byte in &mut base {
        state ^= state.wrapping_shl(13);
        state ^= state.wrapping_shr(17);
        state ^= state.wrapping_shl(5);
        *byte = state.to_le_bytes()[0];
    }
    (
        archive[data..data + compressed_size].to_vec(),
        base.repeat(3),
    )
}

#[cfg(feature = "zstd")]
fn checksum_zstd_zip(path: &[u8], body: &[u8]) -> Vec<u8> {
    let mut encoder = zstd_codec::stream::Encoder::new(Vec::new(), 3).unwrap();
    encoder.include_checksum(true).unwrap();
    encoder.write_all(body).unwrap();
    let compressed = encoder.finish().unwrap();
    assert_ne!(compressed[4] & 0x04, 0, "fixture must carry a checksum");

    let compressed_size = u32::try_from(compressed.len()).unwrap();
    let body_size = u32::try_from(body.len()).unwrap();
    let name_size = u16::try_from(path.len()).unwrap();
    let checksum = libarchive_oxide::filter::crc32(body);
    let mut archive = Vec::new();
    archive.extend_from_slice(b"PK\x03\x04");
    for value in [63_u16, 8, 93, 0, 0] {
        archive.extend_from_slice(&value.to_le_bytes());
    }
    for value in [0_u32; 3] {
        archive.extend_from_slice(&value.to_le_bytes());
    }
    archive.extend_from_slice(&name_size.to_le_bytes());
    archive.extend_from_slice(&0_u16.to_le_bytes());
    archive.extend_from_slice(path);
    archive.extend_from_slice(&compressed);
    archive.extend_from_slice(b"PK\x07\x08");
    for value in [checksum, compressed_size, body_size] {
        archive.extend_from_slice(&value.to_le_bytes());
    }

    let central_offset = u32::try_from(archive.len()).unwrap();
    archive.extend_from_slice(b"PK\x01\x02");
    for value in [0x031e_u16, 63, 8, 93, 0, 0] {
        archive.extend_from_slice(&value.to_le_bytes());
    }
    for value in [checksum, compressed_size, body_size] {
        archive.extend_from_slice(&value.to_le_bytes());
    }
    archive.extend_from_slice(&name_size.to_le_bytes());
    for value in [0_u16; 4] {
        archive.extend_from_slice(&value.to_le_bytes());
    }
    archive.extend_from_slice(&(0o100_644_u32 << 16).to_le_bytes());
    archive.extend_from_slice(&0_u32.to_le_bytes());
    archive.extend_from_slice(path);
    let central_size = u32::try_from(archive.len()).unwrap() - central_offset;

    archive.extend_from_slice(b"PK\x05\x06");
    for value in [0_u16, 0, 1, 1] {
        archive.extend_from_slice(&value.to_le_bytes());
    }
    archive.extend_from_slice(&central_size.to_le_bytes());
    archive.extend_from_slice(&central_offset.to_le_bytes());
    archive.extend_from_slice(&0_u16.to_le_bytes());
    archive
}

fn first_error(bytes: Vec<u8>, limits: Limits) -> ErrorKind {
    let mut reader =
        ArchiveReader::with_format_and_limits(OneByte::new(bytes), FormatId::Zip, limits)
            .expect("construct explicit streaming ZIP reader");
    loop {
        match reader.next_event() {
            Ok(ReaderEvent::Done) => panic!("malformed ZIP unexpectedly completed"),
            Ok(_) => {},
            Err(error) => return error.kind(),
        }
    }
}

fn collect(bytes: Vec<u8>) -> CollectedEntries {
    collect_from(OneByte::new(bytes))
}

fn collect_from<R: Read>(source: R) -> CollectedEntries {
    let mut reader = ArchiveReader::new(source);
    let mut entries = Vec::new();
    let mut current: Option<(Vec<u8>, Vec<u8>)> = None;
    loop {
        match reader.next_event().expect("read streaming ZIP event") {
            ReaderEvent::ArchiveMetadata(_) => {},
            ReaderEvent::Entry(metadata) => {
                current = Some((metadata.path().as_bytes().to_vec(), Vec::new()));
            },
            ReaderEvent::Data(data) => current
                .as_mut()
                .expect("data follows an entry")
                .1
                .extend_from_slice(data),
            ReaderEvent::EndEntry => {
                entries.push(current.take().expect("entry is open"));
            },
            ReaderEvent::Done => return entries,
            _ => panic!("unexpected future reader event"),
        }
    }
}

#[cfg(feature = "aes")]
fn independent_zipcrypto_store(path: &str, body: &[u8], password: &[u8]) -> Vec<u8> {
    independent_zipcrypto(path, body, password, zip::CompressionMethod::Stored)
}

#[cfg(feature = "aes")]
fn independent_zipcrypto(
    path: &str,
    body: &[u8],
    password: &[u8],
    method: zip::CompressionMethod,
) -> Vec<u8> {
    use zip::unstable::write::FileOptionsExt;

    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    let options = SimpleFileOptions::default()
        .compression_method(method)
        .with_deprecated_encryption(password)
        .expect("non-empty ZipCrypto password");
    writer
        .start_file(path, options)
        .expect("start ZipCrypto file");
    writer.write_all(body).expect("write ZipCrypto file");
    writer
        .finish()
        .expect("finish ZipCrypto archive")
        .into_inner()
}

#[cfg(feature = "aes")]
fn streaming_zipcrypto(method: ZipMethod, path: &[u8], body: &[u8], password: &[u8]) -> Vec<u8> {
    let mut writer = ArchiveWriter::with_zipcrypto_password(
        Vec::new(),
        method,
        SecretBytes::from(password),
        Limits::default(),
    );
    let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_bytes(path.to_vec()))
        .size(Some(body.len() as u64))
        .build();
    writer
        .start_entry(&metadata)
        .expect("start ZipCrypto entry");
    for chunk in body.chunks(31) {
        writer.write_data(chunk).expect("write ZipCrypto entry");
    }
    writer.end_entry().expect("end ZipCrypto entry");
    writer.finish().expect("finish ZipCrypto archive")
}

#[cfg(feature = "aes")]
fn streaming_aes(method: ZipMethod, path: &[u8], body: &[u8], password: &[u8]) -> Vec<u8> {
    streaming_aes_strength(method, path, body, password, AesStrength::Bits256)
}

#[cfg(feature = "aes")]
fn streaming_aes_strength(
    method: ZipMethod,
    path: &[u8],
    body: &[u8],
    password: &[u8],
    strength: AesStrength,
) -> Vec<u8> {
    let mut writer = ArchiveWriter::with_zip_password_and_strength(
        Vec::new(),
        method,
        SecretBytes::from(password),
        strength,
        Limits::default(),
    );
    let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_bytes(path.to_vec()))
        .size(Some(body.len() as u64))
        .build();
    writer.start_entry(&metadata).expect("start AES entry");
    for chunk in body.chunks(31) {
        writer.write_data(chunk).expect("write AES entry");
    }
    writer.end_entry().expect("end AES entry");
    writer.finish().expect("finish AES archive")
}

fn descriptor_zip_to_known_size(mut archive: Vec<u8>) -> Vec<u8> {
    let eocd = archive
        .windows(4)
        .rposition(|window| window == b"PK\x05\x06")
        .expect("ZIP end record");
    let central = usize::try_from(u32::from_le_bytes(
        archive[eocd + 16..eocd + 20].try_into().unwrap(),
    ))
    .unwrap();
    let zip64 = u32::from_le_bytes(archive[18..22].try_into().unwrap()) == u32::MAX;
    let descriptor = central - if zip64 { 24 } else { 16 };
    assert_eq!(&archive[descriptor..descriptor + 4], b"PK");
    let flags = u16::from_le_bytes(archive[6..8].try_into().unwrap()) & !8;
    archive[6..8].copy_from_slice(&flags.to_le_bytes());
    let sizes = archive[descriptor + 4..descriptor + 16].to_vec();
    archive[14..26].copy_from_slice(&sizes);
    archive.drain(descriptor..central);

    let central = descriptor;
    let flags = u16::from_le_bytes(archive[central + 8..central + 10].try_into().unwrap()) & !8;
    archive[central + 8..central + 10].copy_from_slice(&flags.to_le_bytes());
    let eocd = find_signature(&archive[central..], 0x0605_4b50) + central;
    archive[eocd + 16..eocd + 20].copy_from_slice(&u32::try_from(central).unwrap().to_le_bytes());
    archive
}

#[cfg(any(feature = "xz", feature = "ppmd"))]
fn signed_descriptor_zip_to_unsigned(mut archive: Vec<u8>) -> Vec<u8> {
    let eocd = archive
        .windows(4)
        .rposition(|window| window == b"PK\x05\x06")
        .expect("ZIP end record");
    let central = usize::try_from(u32::from_le_bytes(
        archive[eocd + 16..eocd + 20].try_into().unwrap(),
    ))
    .unwrap();
    let descriptor = if central >= 16 && &archive[central - 16..central - 12] == b"PK\x07\x08" {
        central - 16
    } else {
        assert!(central >= 24);
        central - 24
    };
    assert_eq!(&archive[descriptor..descriptor + 4], b"PK\x07\x08");
    archive.drain(descriptor..descriptor + 4);
    let shifted_eocd = eocd - 4;
    archive[shifted_eocd + 16..shifted_eocd + 20]
        .copy_from_slice(&u32::try_from(central - 4).unwrap().to_le_bytes());
    archive
}

#[cfg(any(feature = "xz", feature = "ppmd"))]
fn signed_descriptor_zip_to_zip64(mut archive: Vec<u8>) -> Vec<u8> {
    let eocd = archive
        .windows(4)
        .rposition(|window| window == b"PK\x05\x06")
        .expect("ZIP end record");
    let central = usize::try_from(u32::from_le_bytes(
        archive[eocd + 16..eocd + 20].try_into().unwrap(),
    ))
    .unwrap();
    let descriptor = central - 16;
    assert_eq!(&archive[descriptor..descriptor + 4], b"PK\x07\x08");
    archive[4..6].copy_from_slice(&45_u16.to_le_bytes());
    archive[18..26].fill(0xff);
    archive[central + 6..central + 8].copy_from_slice(&45_u16.to_le_bytes());
    let checksum = archive[descriptor + 4..descriptor + 8].to_vec();
    let compressed = u64::from(u32::from_le_bytes(
        archive[descriptor + 8..descriptor + 12].try_into().unwrap(),
    ));
    let uncompressed = u64::from(u32::from_le_bytes(
        archive[descriptor + 12..descriptor + 16]
            .try_into()
            .unwrap(),
    ));
    let mut replacement = Vec::with_capacity(24);
    replacement.extend_from_slice(b"PK\x07\x08");
    replacement.extend_from_slice(&checksum);
    replacement.extend_from_slice(&compressed.to_le_bytes());
    replacement.extend_from_slice(&uncompressed.to_le_bytes());
    archive.splice(descriptor..central, replacement);

    let shifted_central = central + 8;
    let shifted_eocd = eocd + 8;
    archive[shifted_eocd + 16..shifted_eocd + 20]
        .copy_from_slice(&u32::try_from(shifted_central).unwrap().to_le_bytes());
    archive
}

#[cfg(feature = "aes")]
fn local_aes_extra_offset(archive: &[u8]) -> usize {
    let name = usize::from(u16::from_le_bytes(archive[26..28].try_into().unwrap()));
    let extra_len = usize::from(u16::from_le_bytes(archive[28..30].try_into().unwrap()));
    let mut cursor = 30 + name;
    let end = cursor + extra_len;
    while cursor < end {
        let id = u16::from_le_bytes(archive[cursor..cursor + 2].try_into().unwrap());
        let len = usize::from(u16::from_le_bytes(
            archive[cursor + 2..cursor + 4].try_into().unwrap(),
        ));
        if id == 0x9901 {
            return cursor + 4;
        }
        cursor += 4 + len;
    }
    panic!("local AES extra field");
}

#[cfg(feature = "aes")]
fn known_size_zipcrypto_store(path: &[u8], body: &[u8], password: &[u8]) -> Vec<u8> {
    known_size_zipcrypto(path, body, body, password, 0)
}

#[cfg(feature = "aes")]
fn known_size_zipcrypto(
    path: &[u8],
    body: &[u8],
    encoded_body: &[u8],
    password: &[u8],
    method: u16,
) -> Vec<u8> {
    zipcrypto_fixture(path, body, encoded_body, password, method, None)
}

#[cfg(all(feature = "aes", feature = "gzip"))]
fn zipcrypto_deflate64_descriptor(
    path: &[u8],
    body: &[u8],
    encoded_body: &[u8],
    password: &[u8],
    signed: bool,
    zip64: bool,
) -> Vec<u8> {
    zipcrypto_fixture(path, body, encoded_body, password, 9, Some((signed, zip64)))
}

#[cfg(feature = "aes")]
fn zipcrypto_fixture(
    path: &[u8],
    body: &[u8],
    encoded_body: &[u8],
    password: &[u8],
    method: u16,
    descriptor: Option<(bool, bool)>,
) -> Vec<u8> {
    let checksum = libarchive_oxide::filter::crc32(body);
    let mut plaintext = vec![0x5a; 12];
    plaintext[11] = if descriptor.is_some() {
        0
    } else {
        (checksum >> 24) as u8
    };
    plaintext.extend_from_slice(encoded_body);
    let mut keys = [0x1234_5678, 0x2345_6789, 0x3456_7890];
    for &byte in password {
        zipcrypto_update(&mut keys, byte);
    }
    for byte in &mut plaintext {
        let clear = *byte;
        *byte ^= zipcrypto_stream_byte(keys);
        zipcrypto_update(&mut keys, clear);
    }

    let compressed = u32::try_from(plaintext.len()).unwrap();
    let uncompressed = u32::try_from(body.len()).unwrap();
    let name_length = u16::try_from(path.len()).unwrap();
    let (signed, zip64) = descriptor.unwrap_or((false, false));
    let flags = 1 | if descriptor.is_some() { 8 } else { 0 };
    let version_needed = if zip64 {
        45
    } else if method == 9 {
        21
    } else {
        20
    };
    let mut archive = Vec::new();
    archive.extend_from_slice(b"PK\x03\x04");
    for value in [version_needed, flags, method, 0, 0] {
        archive.extend_from_slice(&value.to_le_bytes());
    }
    let local_crc = if descriptor.is_some() { 0 } else { checksum };
    let local_compressed = if descriptor.is_some() {
        if zip64 { u32::MAX } else { 0 }
    } else {
        compressed
    };
    let local_uncompressed = if descriptor.is_some() {
        if zip64 { u32::MAX } else { 0 }
    } else {
        uncompressed
    };
    for value in [local_crc, local_compressed, local_uncompressed] {
        archive.extend_from_slice(&value.to_le_bytes());
    }
    archive.extend_from_slice(&name_length.to_le_bytes());
    archive.extend_from_slice(&0_u16.to_le_bytes());
    archive.extend_from_slice(path);
    archive.extend_from_slice(&plaintext);
    if descriptor.is_some() {
        if signed {
            archive.extend_from_slice(b"PK\x07\x08");
        }
        archive.extend_from_slice(&checksum.to_le_bytes());
        if zip64 {
            archive.extend_from_slice(&u64::from(compressed).to_le_bytes());
            archive.extend_from_slice(&u64::from(uncompressed).to_le_bytes());
        } else {
            archive.extend_from_slice(&compressed.to_le_bytes());
            archive.extend_from_slice(&uncompressed.to_le_bytes());
        }
    }

    let central_offset = u32::try_from(archive.len()).unwrap();
    archive.extend_from_slice(b"PK\x01\x02");
    for value in [0x031e_u16, version_needed, flags, method, 0, 0] {
        archive.extend_from_slice(&value.to_le_bytes());
    }
    for value in [checksum, compressed, uncompressed] {
        archive.extend_from_slice(&value.to_le_bytes());
    }
    archive.extend_from_slice(&name_length.to_le_bytes());
    for value in [0_u16; 4] {
        archive.extend_from_slice(&value.to_le_bytes());
    }
    archive.extend_from_slice(&(0o100_644_u32 << 16).to_le_bytes());
    archive.extend_from_slice(&0_u32.to_le_bytes());
    archive.extend_from_slice(path);
    let central_size = u32::try_from(archive.len()).unwrap() - central_offset;

    archive.extend_from_slice(b"PK\x05\x06");
    for value in [0_u16, 0, 1, 1] {
        archive.extend_from_slice(&value.to_le_bytes());
    }
    archive.extend_from_slice(&central_size.to_le_bytes());
    archive.extend_from_slice(&central_offset.to_le_bytes());
    archive.extend_from_slice(&0_u16.to_le_bytes());
    archive
}

#[cfg(feature = "aes")]
fn independent_encoded_body(method: zip::CompressionMethod, body: &[u8]) -> Vec<u8> {
    let archive = independent_zip(method, "encoded.bin", body);
    let name = usize::from(u16::from_le_bytes([archive[26], archive[27]]));
    let extra = usize::from(u16::from_le_bytes([archive[28], archive[29]]));
    let compressed =
        usize::try_from(u32::from_le_bytes(archive[18..22].try_into().unwrap())).unwrap();
    archive[30 + name + extra..30 + name + extra + compressed].to_vec()
}

#[cfg(feature = "aes")]
fn password_options(candidates: impl IntoIterator<Item = Vec<u8>>) -> OpenOptions {
    OpenOptions::new()
        .with_format(Some(FormatId::Zip))
        .with_password_provider(Arc::new(PasswordCandidates::new(
            candidates.into_iter().map(SecretBytes::from),
        )))
}

#[cfg(feature = "aes")]
fn collect_with_password<R: Read>(
    source: R,
    password: &[u8],
) -> Result<CollectedEntries, libarchive_oxide::Error> {
    let options = password_options([password.to_vec()]);
    let mut reader = ArchiveReader::with_options(source, &options)?;
    let mut entries = Vec::new();
    let mut current: Option<(Vec<u8>, Vec<u8>)> = None;
    loop {
        match reader.next_event()? {
            ReaderEvent::ArchiveMetadata(_) => {},
            ReaderEvent::Entry(metadata) => {
                current = Some((metadata.path().as_bytes().to_vec(), Vec::new()));
            },
            ReaderEvent::Data(data) => current
                .as_mut()
                .expect("data follows an entry")
                .1
                .extend_from_slice(data),
            ReaderEvent::EndEntry => {
                entries.push(current.take().expect("entry is open"));
            },
            ReaderEvent::Done => return Ok(entries),
            _ => panic!("unexpected future reader event"),
        }
    }
}

#[cfg(feature = "aes")]
#[test]
fn forward_only_reader_decodes_aes_store_with_signed_descriptor() {
    let password = b"AES stream password";
    let body = b"authenticated stored payload with a signed descriptor".repeat(257);
    for strength in [
        AesStrength::Bits128,
        AesStrength::Bits192,
        AesStrength::Bits256,
    ] {
        let archive =
            streaming_aes_strength(ZipMethod::Store, b"secret.aes", &body, password, strength);
        assert_eq!(
            collect_with_password(OneByte::new(archive), password).expect("decrypt AES Store"),
            vec![(b"secret.aes".to_vec(), body.clone())],
            "{strength:?}"
        );
    }
}

#[cfg(feature = "aes")]
#[test]
fn forward_only_reader_decodes_known_size_aes_store() {
    let password = b"known AES password";
    let body = b"known-size authenticated stored payload".repeat(257);
    let archive = streaming_aes(ZipMethod::Store, b"known.aes", &body, password);
    let archive = descriptor_zip_to_known_size(archive);
    assert_eq!(u16::from_le_bytes(archive[6..8].try_into().unwrap()) & 8, 0);

    assert_eq!(
        collect_with_password(OneByte::new(archive), password).expect("known AES Store"),
        vec![(b"known.aes".to_vec(), body)]
    );
}

#[cfg(feature = "aes")]
#[test]
fn forward_only_reader_decodes_aes_deflate_with_signed_descriptor() {
    let password = b"AES Deflate stream password";
    let body = b"authenticated Deflate payload with a signed descriptor".repeat(4096);
    let archive = streaming_aes(ZipMethod::Deflate, b"secret.deflate.aes", &body, password);

    assert_eq!(
        collect_with_password(OneByte::new(archive), password).expect("decrypt AES Deflate"),
        vec![(b"secret.deflate.aes".to_vec(), body)]
    );
}

#[cfg(feature = "aes")]
#[test]
fn forward_only_reader_decodes_known_size_aes_deflate() {
    let password = b"known AES Deflate password";
    let body = b"known-size authenticated Deflate payload".repeat(4096);
    let archive = streaming_aes(ZipMethod::Deflate, b"known.deflate.aes", &body, password);
    let archive = descriptor_zip_to_known_size(archive);

    assert_eq!(
        collect_with_password(OneByte::new(archive), password).expect("known AES Deflate"),
        vec![(b"known.deflate.aes".to_vec(), body)]
    );
}

#[cfg(feature = "aes")]
#[test]
fn forward_only_aes_deflate_types_authentication_truncation_and_limits() {
    let password = b"bounded AES Deflate password";
    let body = b"bounded authenticated Deflate payload".repeat(4096);
    let archive = streaming_aes(ZipMethod::Deflate, b"bounded.deflate.aes", &body, password);

    let wrong = collect_with_password(OneByte::new(archive.clone()), b"incorrect")
        .expect_err("wrong AES Deflate password");
    assert_eq!(wrong.kind(), ErrorKind::Integrity);

    let name = usize::from(u16::from_le_bytes(archive[26..28].try_into().unwrap()));
    let extra = usize::from(u16::from_le_bytes(archive[28..30].try_into().unwrap()));
    let payload = 30 + name + extra;
    let mut tampered_ciphertext = archive.clone();
    tampered_ciphertext[payload + 18] ^= 0x80;
    let tamper = collect_with_password(OneByte::new(tampered_ciphertext), password)
        .expect_err("tampered AES Deflate ciphertext");
    assert_eq!(tamper.kind(), ErrorKind::Integrity);

    let central = find_signature(&archive, 0x0201_4b50);
    let mut tampered_tag = archive.clone();
    tampered_tag[central - 17] ^= 0x80;
    let authentication = collect_with_password(OneByte::new(tampered_tag), password)
        .expect_err("tampered AES Deflate authentication");
    assert_eq!(authentication.kind(), ErrorKind::Integrity);

    let truncated = archive[..central - 8].to_vec();
    let truncation = collect_with_password(OneByte::new(truncated), password)
        .expect_err("truncated AES Deflate descriptor");
    assert_eq!(truncation.kind(), ErrorKind::Malformed);

    let limited = password_options([password.to_vec()])
        .with_limits(Limits::default().with_decoded_total(Some(1024)));
    let mut reader = ArchiveReader::with_options(OneByte::new(archive), &limited)
        .expect("limited AES Deflate reader");
    let limit = loop {
        match reader.next_event() {
            Ok(ReaderEvent::Done) => panic!("AES Deflate bomb unexpectedly completed"),
            Ok(_) => {},
            Err(error) => break error,
        }
    };
    assert_eq!(limit.kind(), ErrorKind::Limit);
}

#[cfg(all(feature = "aes", feature = "bzip2", feature = "zstd", feature = "xz"))]
#[test]
fn forward_only_reader_decodes_aes_pipeline_descriptors() {
    let password = b"AES pipeline stream password";
    let body = b"authenticated pipeline payload with a signed descriptor".repeat(4096);
    for method in [
        ZipMethod::Bzip2,
        ZipMethod::Lzma,
        ZipMethod::Ppmd8,
        ZipMethod::Zstd,
        ZipMethod::Xz,
    ] {
        let archive = streaming_aes(method, b"secret.pipeline.aes", &body, password);
        assert_eq!(
            collect_with_password(OneByte::new(archive), password).expect("decrypt AES pipeline"),
            vec![(b"secret.pipeline.aes".to_vec(), body.clone())],
            "{method:?}"
        );
    }
}

#[cfg(all(feature = "aes", feature = "xz"))]
#[test]
fn forward_only_reader_accepts_aes_xz_padding_before_authentication() {
    let password = b"AES XZ padding password";
    let body = b"authenticated XZ padding payload".repeat(4096);
    let archive = streaming_aes(ZipMethod::Xz, b"padding.aes.xz", &body, password);
    let archive = add_aes_xz_padding(archive, password);

    assert_eq!(
        collect_with_password(OneByte::new(archive), password).expect("AES XZ padding"),
        vec![(b"padding.aes.xz".to_vec(), body)]
    );
}

#[cfg(all(feature = "aes", feature = "bzip2", feature = "zstd", feature = "xz"))]
#[test]
fn forward_only_reader_decodes_known_size_aes_pipelines() {
    let password = b"known AES pipeline password";
    let body = b"known-size authenticated pipeline payload".repeat(4096);
    for method in [
        ZipMethod::Bzip2,
        ZipMethod::Lzma,
        ZipMethod::Ppmd8,
        ZipMethod::Zstd,
        ZipMethod::Xz,
    ] {
        let archive = streaming_aes(method, b"known.pipeline.aes", &body, password);
        let archive = descriptor_zip_to_known_size(archive);
        assert_eq!(
            collect_with_password(OneByte::new(archive), password).expect("known AES pipeline"),
            vec![(b"known.pipeline.aes".to_vec(), body.clone())],
            "{method:?}"
        );
    }
}

#[cfg(all(feature = "aes", feature = "bzip2", feature = "zstd", feature = "xz"))]
#[test]
fn forward_only_aes_pipelines_type_authentication_truncation_and_limits() {
    let password = b"bounded AES pipeline password";
    let body = b"bounded authenticated pipeline payload".repeat(4096);
    for method in [
        ZipMethod::Bzip2,
        ZipMethod::Lzma,
        ZipMethod::Ppmd8,
        ZipMethod::Zstd,
        ZipMethod::Xz,
    ] {
        let archive = streaming_aes(method, b"bounded.pipeline.aes", &body, password);

        let wrong =
            collect_with_password(OneByte::new(archive.clone()), b"wrong pipeline password")
                .expect_err("wrong AES pipeline password");
        assert_eq!(wrong.kind(), ErrorKind::Integrity, "{method:?}");

        let name = usize::from(u16::from_le_bytes(archive[26..28].try_into().unwrap()));
        let extra = usize::from(u16::from_le_bytes(archive[28..30].try_into().unwrap()));
        let payload = 30 + name + extra;
        let mut tampered_ciphertext = archive.clone();
        tampered_ciphertext[payload + 18] ^= 0x80;
        let tamper = collect_with_password(OneByte::new(tampered_ciphertext), password)
            .expect_err("tampered AES pipeline ciphertext");
        assert_eq!(tamper.kind(), ErrorKind::Integrity, "{method:?}");

        let central = find_signature(&archive, 0x0201_4b50);
        let mut tampered_tag = archive.clone();
        tampered_tag[central - 17] ^= 0x80;
        let authentication = collect_with_password(OneByte::new(tampered_tag), password)
            .expect_err("tampered AES pipeline authentication");
        assert_eq!(authentication.kind(), ErrorKind::Integrity, "{method:?}");

        let truncated = archive[..central - 8].to_vec();
        let truncation = collect_with_password(OneByte::new(truncated), password)
            .expect_err("truncated AES pipeline descriptor");
        assert_eq!(truncation.kind(), ErrorKind::Malformed, "{method:?}");

        let limited = password_options([password.to_vec()])
            .with_limits(Limits::default().with_decoded_total(Some(1024)));
        let mut reader = ArchiveReader::with_options(OneByte::new(archive), &limited)
            .expect("limited AES pipeline reader");
        let limit = loop {
            match reader.next_event() {
                Ok(ReaderEvent::Done) => panic!("AES pipeline bomb unexpectedly completed"),
                Ok(_) => {},
                Err(error) => break error,
            }
        };
        assert_eq!(limit.kind(), ErrorKind::Limit, "{method:?}");
    }
}

#[cfg(feature = "aes")]
#[test]
fn forward_only_aes_store_types_password_authentication_truncation_and_limits() {
    let password = b"bounded AES password";
    let body = b"bounded authenticated stored payload".repeat(4096);
    let archive = streaming_aes(ZipMethod::Store, b"bounded.aes", &body, password);

    let wrong = collect_with_password(OneByte::new(archive.clone()), b"incorrect")
        .expect_err("wrong AES password");
    assert_eq!(wrong.kind(), ErrorKind::Integrity);

    let options = password_options([
        b"incorrect candidate".to_vec(),
        password.to_vec(),
        b"unused candidate".to_vec(),
    ]);
    let mut candidate_reader =
        ArchiveReader::with_options(OneByte::new(archive.clone()), &options).expect("AES reader");
    let mut candidate_body = Vec::new();
    loop {
        match candidate_reader
            .next_event()
            .expect("AES candidate succeeds")
        {
            ReaderEvent::Data(data) => candidate_body.extend_from_slice(data),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(candidate_body, body);

    let mut without_password =
        ArchiveReader::with_format(OneByte::new(archive.clone()), FormatId::Zip).unwrap();
    let missing = loop {
        match without_password.next_event() {
            Ok(ReaderEvent::Done) => panic!("AES ZIP completed without a password"),
            Ok(_) => {},
            Err(error) => break error,
        }
    };
    assert_eq!(missing.kind(), ErrorKind::Unsupported);

    let name = usize::from(u16::from_le_bytes(archive[26..28].try_into().unwrap()));
    let extra = usize::from(u16::from_le_bytes(archive[28..30].try_into().unwrap()));
    let payload = 30 + name + extra;
    let mut tampered_ciphertext = archive.clone();
    tampered_ciphertext[payload + 18] ^= 0x80;
    let tamper = collect_with_password(OneByte::new(tampered_ciphertext), password)
        .expect_err("tampered AES ciphertext");
    assert_eq!(tamper.kind(), ErrorKind::Integrity);

    let central = find_signature(&archive, 0x0201_4b50);
    let mut tampered_tag = archive.clone();
    tampered_tag[central - 17] ^= 0x80;
    let authentication = collect_with_password(OneByte::new(tampered_tag), password)
        .expect_err("tampered AES authentication");
    assert_eq!(authentication.kind(), ErrorKind::Integrity);

    let truncated = archive[..central - 8].to_vec();
    let truncation = collect_with_password(OneByte::new(truncated), password)
        .expect_err("truncated AES descriptor");
    assert_eq!(truncation.kind(), ErrorKind::Malformed);

    let limited = password_options([password.to_vec()])
        .with_limits(Limits::default().with_decoded_total(Some(1024)));
    let mut reader =
        ArchiveReader::with_options(OneByte::new(archive), &limited).expect("limited AES reader");
    let limit = loop {
        match reader.next_event() {
            Ok(ReaderEvent::Done) => panic!("AES bomb unexpectedly completed"),
            Ok(_) => {},
            Err(error) => break error,
        }
    };
    assert_eq!(limit.kind(), ErrorKind::Limit);
}

#[cfg(feature = "aes")]
#[test]
fn forward_only_aes_extra_profile_failures_are_typed() {
    let password = b"AES extra profile password";
    let body = b"AES extra profile payload".repeat(31);
    let archive = streaming_aes(ZipMethod::Store, b"profile.aes", &body, password);
    let extra = local_aes_extra_offset(&archive);

    let mut ae1 = archive.clone();
    ae1[extra..extra + 2].copy_from_slice(&1_u16.to_le_bytes());
    let error = collect_with_password(OneByte::new(ae1), password).expect_err("AE-1 profile");
    assert_eq!(error.kind(), ErrorKind::Unsupported);

    let mut invalid_strength = archive.clone();
    invalid_strength[extra + 4] = 4;
    let error = collect_with_password(OneByte::new(invalid_strength), password)
        .expect_err("invalid AES strength");
    assert_eq!(error.kind(), ErrorKind::Malformed);

    let mut missing_flag = archive;
    let flags = u16::from_le_bytes(missing_flag[6..8].try_into().unwrap()) & !1;
    missing_flag[6..8].copy_from_slice(&flags.to_le_bytes());
    let error = collect_with_password(OneByte::new(missing_flag), password)
        .expect_err("missing AES encrypted flag");
    assert_eq!(error.kind(), ErrorKind::Malformed);
}

#[cfg(feature = "aes")]
#[test]
fn forward_only_reader_decodes_zipcrypto_store_with_signed_descriptor() {
    let password = b"stream password";
    let body = b"known-size encrypted store payload".repeat(31);
    let archive = independent_zipcrypto_store("secret.bin", &body, password);
    let expected = vec![(b"secret.bin".to_vec(), body)];

    assert_eq!(
        collect_with_password(Cursor::new(archive.clone()), password).expect("decrypt ZipCrypto"),
        expected
    );
    assert_eq!(
        collect_with_password(OneByte::new(archive), password).expect("one-byte ZipCrypto"),
        expected
    );
}

#[cfg(feature = "aes")]
#[test]
fn forward_only_reader_decodes_zipcrypto_deflate_with_signed_descriptor() {
    let password = b"deflate stream password";
    let body = b"encrypted deflate payload with a signed descriptor".repeat(257);
    let archive = independent_zipcrypto(
        "secret.deflate",
        &body,
        password,
        zip::CompressionMethod::Deflated,
    );
    let expected = vec![(b"secret.deflate".to_vec(), body)];

    assert_eq!(
        collect_with_password(Cursor::new(archive.clone()), password)
            .expect("decrypt ZipCrypto Deflate"),
        expected
    );
    assert_eq!(
        collect_with_password(OneByte::new(archive), password).expect("one-byte ZipCrypto Deflate"),
        expected
    );
}

#[cfg(all(feature = "aes", feature = "bzip2", feature = "zstd", feature = "xz"))]
#[test]
fn forward_only_reader_decodes_zipcrypto_pipeline_descriptors() {
    let password = b"pipeline stream password";
    let body = b"encrypted pipeline payload with a signed descriptor".repeat(257);
    for method in [
        ZipMethod::Bzip2,
        ZipMethod::Lzma,
        ZipMethod::Ppmd8,
        ZipMethod::Zstd,
        ZipMethod::Xz,
    ] {
        let archive = streaming_zipcrypto(method, b"secret.pipeline", &body, password);
        assert_eq!(
            collect_with_password(OneByte::new(archive), password)
                .expect("decrypt ZipCrypto pipeline"),
            vec![(b"secret.pipeline".to_vec(), body.clone())],
            "{method:?}"
        );
    }
}

#[cfg(all(feature = "aes", feature = "xz"))]
#[test]
fn forward_only_encrypted_lzma_accepts_unsigned_and_zip64_descriptors() {
    let password = b"LZMA encrypted descriptor password";
    let body = b"encrypted LZMA descriptor boundary".repeat(4096);

    let zipcrypto = streaming_zipcrypto(ZipMethod::Lzma, b"unsigned.zipcrypto", &body, password);
    let zipcrypto = signed_descriptor_zip_to_unsigned(zipcrypto);
    assert_eq!(
        collect_with_password(OneByte::new(zipcrypto), password).expect("unsigned ZipCrypto LZMA"),
        vec![(b"unsigned.zipcrypto".to_vec(), body.clone())]
    );

    let zipcrypto_zip64 = signed_descriptor_zip_to_zip64(streaming_zipcrypto(
        ZipMethod::Lzma,
        b"zip64.zipcrypto",
        &body,
        password,
    ));
    assert_eq!(
        collect_with_password(OneByte::new(zipcrypto_zip64.clone()), password)
            .expect("ZIP64 ZipCrypto LZMA"),
        vec![(b"zip64.zipcrypto".to_vec(), body.clone())]
    );
    assert_eq!(
        collect_with_password(
            OneByte::new(signed_descriptor_zip_to_unsigned(zipcrypto_zip64)),
            password,
        )
        .expect("unsigned ZIP64 ZipCrypto LZMA"),
        vec![(b"zip64.zipcrypto".to_vec(), body.clone())]
    );

    let aes = streaming_aes(ZipMethod::Lzma, b"unsigned.aes", &body, password);
    let aes = signed_descriptor_zip_to_unsigned(aes);
    assert_eq!(
        collect_with_password(OneByte::new(aes), password).expect("unsigned AES LZMA"),
        vec![(b"unsigned.aes".to_vec(), body.clone())]
    );

    let aes_zip64 = signed_descriptor_zip_to_zip64(streaming_aes_strength(
        ZipMethod::Lzma,
        b"zip64.aes",
        &body,
        password,
        AesStrength::Bits256,
    ));
    assert_eq!(
        collect_with_password(OneByte::new(aes_zip64.clone()), password).expect("ZIP64 AES LZMA"),
        vec![(b"zip64.aes".to_vec(), body.clone())]
    );
    assert_eq!(
        collect_with_password(
            OneByte::new(signed_descriptor_zip_to_unsigned(aes_zip64)),
            password,
        )
        .expect("unsigned ZIP64 AES LZMA"),
        vec![(b"zip64.aes".to_vec(), body)]
    );
}

#[cfg(all(feature = "aes", feature = "ppmd"))]
#[test]
fn forward_only_encrypted_ppmd_accepts_unsigned_and_zip64_descriptors() {
    let password = b"PPMd encrypted descriptor password";
    let body = b"encrypted PPMd descriptor boundary".repeat(4096);

    let zipcrypto = streaming_zipcrypto(ZipMethod::Ppmd8, b"unsigned.zipcrypto", &body, password);
    assert_eq!(
        collect_with_password(
            OneByte::new(signed_descriptor_zip_to_unsigned(zipcrypto)),
            password,
        )
        .expect("unsigned ZipCrypto PPMd"),
        vec![(b"unsigned.zipcrypto".to_vec(), body.clone())]
    );

    let zipcrypto_zip64 = signed_descriptor_zip_to_zip64(streaming_zipcrypto(
        ZipMethod::Ppmd8,
        b"zip64.zipcrypto",
        &body,
        password,
    ));
    assert_eq!(
        collect_with_password(OneByte::new(zipcrypto_zip64.clone()), password)
            .expect("ZIP64 ZipCrypto PPMd"),
        vec![(b"zip64.zipcrypto".to_vec(), body.clone())]
    );
    assert_eq!(
        collect_with_password(
            OneByte::new(signed_descriptor_zip_to_unsigned(zipcrypto_zip64)),
            password,
        )
        .expect("unsigned ZIP64 ZipCrypto PPMd"),
        vec![(b"zip64.zipcrypto".to_vec(), body.clone())]
    );

    let aes = streaming_aes(ZipMethod::Ppmd8, b"unsigned.aes", &body, password);
    assert_eq!(
        collect_with_password(
            OneByte::new(signed_descriptor_zip_to_unsigned(aes)),
            password,
        )
        .expect("unsigned AES PPMd"),
        vec![(b"unsigned.aes".to_vec(), body.clone())]
    );

    let aes_zip64 = signed_descriptor_zip_to_zip64(streaming_aes_strength(
        ZipMethod::Ppmd8,
        b"zip64.aes",
        &body,
        password,
        AesStrength::Bits256,
    ));
    assert_eq!(
        collect_with_password(OneByte::new(aes_zip64.clone()), password).expect("ZIP64 AES PPMd"),
        vec![(b"zip64.aes".to_vec(), body.clone())]
    );
    assert_eq!(
        collect_with_password(
            OneByte::new(signed_descriptor_zip_to_unsigned(aes_zip64)),
            password,
        )
        .expect("unsigned ZIP64 AES PPMd"),
        vec![(b"zip64.aes".to_vec(), body)]
    );
}

#[cfg(all(feature = "aes", feature = "xz"))]
#[test]
fn forward_only_reader_accepts_encrypted_xz_padding_before_descriptor() {
    let password = b"encrypted XZ padding password";
    let body = b"encrypted XZ padding payload".repeat(257);
    let archive = streaming_zipcrypto(ZipMethod::Xz, b"padding.xz", &body, password);
    let archive = add_encrypted_xz_padding(archive, password);

    assert_eq!(
        collect_with_password(OneByte::new(archive), password).expect("encrypted XZ padding"),
        vec![(b"padding.xz".to_vec(), body)]
    );
}

#[cfg(all(feature = "aes", feature = "bzip2", feature = "zstd", feature = "xz"))]
#[test]
fn forward_only_reader_decodes_known_size_zipcrypto_pipelines() {
    let password = b"known pipeline password";
    let body = b"known-size encrypted pipeline payload".repeat(257);
    for (zip_method, raw_method, numeric) in [
        (zip::CompressionMethod::Bzip2, ZipMethod::Bzip2, 12),
        (zip::CompressionMethod::Lzma, ZipMethod::Lzma, 14),
        (zip::CompressionMethod::Ppmd, ZipMethod::Ppmd8, 98),
        (zip::CompressionMethod::Zstd, ZipMethod::Zstd, 93),
        (zip::CompressionMethod::XZ, ZipMethod::Xz, 95),
    ] {
        let compressed = if numeric == 14 {
            let encoded = streaming_zip(ZipMethod::Lzma, &[(b"encoded.lzma", &body)]);
            let name = usize::from(u16::from_le_bytes(encoded[26..28].try_into().unwrap()));
            let extra = usize::from(u16::from_le_bytes(encoded[28..30].try_into().unwrap()));
            let payload = 30 + name + extra;
            let central = find_signature(&encoded, 0x0201_4b50);
            encoded[payload..central - 16].to_vec()
        } else {
            independent_encoded_body(zip_method, &body)
        };
        let archive =
            known_size_zipcrypto(b"known.pipeline", &body, &compressed, password, numeric);
        assert_eq!(
            collect_with_password(OneByte::new(archive), password)
                .expect("known ZipCrypto pipeline"),
            vec![(b"known.pipeline".to_vec(), body.clone())],
            "{raw_method:?}"
        );
    }
}

#[cfg(all(feature = "aes", feature = "bzip2", feature = "zstd", feature = "xz"))]
#[test]
fn forward_only_zipcrypto_pipelines_type_integrity_truncation_and_limits() {
    let password = b"bounded pipeline password";
    let body = b"bounded encrypted pipeline payload".repeat(4096);
    for method in [
        ZipMethod::Bzip2,
        ZipMethod::Lzma,
        ZipMethod::Ppmd8,
        ZipMethod::Zstd,
        ZipMethod::Xz,
    ] {
        let archive = streaming_zipcrypto(method, b"bounded.pipeline", &body, password);
        let wrong =
            collect_with_password(OneByte::new(archive.clone()), b"wrong pipeline password")
                .expect_err("wrong pipeline password");
        assert_eq!(wrong.kind(), ErrorKind::Integrity, "{method:?}");

        if matches!(method, ZipMethod::Ppmd8) {
            let options = password_options([password.to_vec()])
                .with_limits(Limits::default().with_codec_memory(Some(1024 * 1024)));
            let mut reader = ArchiveReader::with_options(OneByte::new(archive.clone()), &options)
                .expect("codec-limited PPMd reader");
            let limit = loop {
                match reader.next_event() {
                    Ok(ReaderEvent::Done) => panic!("PPMd model limit unexpectedly completed"),
                    Ok(_) => {},
                    Err(error) => break error,
                }
            };
            assert_eq!(limit.kind(), ErrorKind::Limit);
        }

        let name = usize::from(u16::from_le_bytes([archive[26], archive[27]]));
        let extra = usize::from(u16::from_le_bytes([archive[28], archive[29]]));
        let mut tampered = archive.clone();
        tampered[30 + name + extra + 12] ^= 0x80;
        let tamper = collect_with_password(OneByte::new(tampered), password)
            .expect_err("tampered pipeline ciphertext");
        assert_eq!(tamper.kind(), ErrorKind::Integrity, "{method:?}");

        let central = find_signature(&archive, 0x0201_4b50);
        let truncated = archive[..central - 8].to_vec();
        let truncation = collect_with_password(OneByte::new(truncated), password)
            .expect_err("truncated pipeline descriptor");
        assert_eq!(truncation.kind(), ErrorKind::Malformed, "{method:?}");

        let limited = password_options([password.to_vec()])
            .with_limits(Limits::default().with_decoded_total(Some(1024)));
        let mut reader =
            ArchiveReader::with_options(OneByte::new(archive), &limited).expect("limited reader");
        let limit = loop {
            match reader.next_event() {
                Ok(ReaderEvent::Done) => panic!("pipeline bomb unexpectedly completed"),
                Ok(_) => {},
                Err(error) => break error,
            }
        };
        assert_eq!(limit.kind(), ErrorKind::Limit, "{method:?}");
    }
}

#[cfg(feature = "aes")]
#[test]
fn forward_only_reader_decodes_known_size_zipcrypto_deflate() {
    let password = b"known deflate password";
    let body = b"known-size encrypted deflate payload".repeat(257);
    let mut encoder =
        flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&body).unwrap();
    let compressed = encoder.finish().unwrap();
    let archive = known_size_zipcrypto(b"known.deflate", &body, &compressed, password, 8);

    assert_eq!(
        collect_with_password(OneByte::new(archive), password).expect("known ZipCrypto Deflate"),
        vec![(b"known.deflate".to_vec(), body)]
    );
}

#[cfg(all(feature = "aes", feature = "gzip"))]
#[test]
fn forward_only_reader_decodes_zipcrypto_deflate64_known_and_descriptors() {
    let password = b"Deflate64 traditional password";
    let body = b"traditional encrypted Deflate64 payload".repeat(4096);
    let compressed = stored_deflate64(&body);
    let known = known_size_zipcrypto(b"known.d64", &body, &compressed, password, 9);
    assert_eq!(
        collect_with_password(OneByte::new(known), password).expect("known ZipCrypto Deflate64"),
        vec![(b"known.d64".to_vec(), body.clone())]
    );

    for (signed, zip64) in [(true, false), (false, false), (true, true), (false, true)] {
        let archive = zipcrypto_deflate64_descriptor(
            b"descriptor.d64",
            &body,
            &compressed,
            password,
            signed,
            zip64,
        );
        let expected = vec![(b"descriptor.d64".to_vec(), body.clone())];
        assert_eq!(
            collect_with_password(OneByte::new(archive.clone()), password)
                .expect("one-byte ZipCrypto Deflate64 descriptor"),
            expected
        );
        assert_eq!(
            collect_with_password(Cursor::new(archive), password)
                .expect("buffered ZipCrypto Deflate64 descriptor"),
            expected
        );
    }

    let (compressed, body) = official_wide_deflate64_member();
    let archive = zipcrypto_deflate64_descriptor(
        b"wide-window.bin",
        &body,
        &compressed,
        password,
        true,
        false,
    );
    assert_eq!(
        collect_with_password(Cursor::new(archive), password)
            .expect("dynamic ZipCrypto Deflate64 descriptor"),
        vec![(b"wide-window.bin".to_vec(), body)]
    );
}

#[cfg(all(feature = "aes", feature = "gzip"))]
#[test]
fn forward_only_zipcrypto_deflate64_types_integrity_truncation_and_limits() {
    let password = b"bounded Deflate64 traditional password";
    let body = b"bounded traditional encrypted Deflate64 payload".repeat(4096);
    let compressed = stored_deflate64(&body);
    let archive =
        zipcrypto_deflate64_descriptor(b"bounded.d64", &body, &compressed, password, true, false);

    let wrong = collect_with_password(OneByte::new(archive.clone()), b"incorrect")
        .expect_err("wrong Deflate64 password");
    assert_eq!(wrong.kind(), ErrorKind::Integrity);

    let name = usize::from(u16::from_le_bytes([archive[26], archive[27]]));
    let extra = usize::from(u16::from_le_bytes([archive[28], archive[29]]));
    let mut tampered = archive.clone();
    tampered[30 + name + extra + 12] ^= 0x80;
    let tamper = collect_with_password(OneByte::new(tampered), password)
        .expect_err("tampered Deflate64 ciphertext");
    assert_eq!(tamper.kind(), ErrorKind::Integrity);

    let descriptor = find_signature(&archive, 0x0807_4b50);
    for offset in [descriptor + 4, descriptor + 8, descriptor + 12] {
        let mut mismatched = archive.clone();
        mismatched[offset] ^= 0x80;
        let error = collect_with_password(OneByte::new(mismatched), password)
            .expect_err("mismatched Deflate64 descriptor");
        assert_eq!(error.kind(), ErrorKind::Integrity);
    }

    let truncated = archive[..descriptor + 10].to_vec();
    let truncation = collect_with_password(OneByte::new(truncated), password)
        .expect_err("truncated Deflate64 descriptor");
    assert_eq!(truncation.kind(), ErrorKind::Malformed);

    let limited = password_options([password.to_vec()])
        .with_limits(Limits::default().with_decoded_total(Some(1024)));
    let mut reader =
        ArchiveReader::with_options(OneByte::new(archive), &limited).expect("limited reader");
    let limit = loop {
        match reader.next_event() {
            Ok(ReaderEvent::Done) => panic!("Deflate64 bomb unexpectedly completed"),
            Ok(_) => {},
            Err(error) => break error,
        }
    };
    assert_eq!(limit.kind(), ErrorKind::Limit);
}

#[cfg(feature = "aes")]
#[test]
fn forward_only_zipcrypto_deflate_types_integrity_truncation_and_limits() {
    let password = b"bounded deflate password";
    let body = b"bounded encrypted deflate payload".repeat(4096);
    let archive = independent_zipcrypto(
        "bounded.deflate",
        &body,
        password,
        zip::CompressionMethod::Deflated,
    );

    let wrong = collect_with_password(OneByte::new(archive.clone()), b"incorrect")
        .expect_err("wrong Deflate password");
    assert_eq!(wrong.kind(), ErrorKind::Integrity);

    let name = usize::from(u16::from_le_bytes([archive[26], archive[27]]));
    let extra = usize::from(u16::from_le_bytes([archive[28], archive[29]]));
    let mut tampered = archive.clone();
    tampered[30 + name + extra + 12] ^= 0x80;
    let tamper = collect_with_password(OneByte::new(tampered), password)
        .expect_err("tampered Deflate ciphertext");
    assert_eq!(tamper.kind(), ErrorKind::Integrity);

    let central = find_signature(&archive, 0x0201_4b50);
    let truncated = archive[..central - 18].to_vec();
    let truncation = collect_with_password(OneByte::new(truncated), password)
        .expect_err("truncated Deflate ciphertext");
    assert_eq!(truncation.kind(), ErrorKind::Malformed);

    let limited = password_options([password.to_vec()])
        .with_limits(Limits::default().with_decoded_total(Some(1024)));
    let mut reader =
        ArchiveReader::with_options(OneByte::new(archive), &limited).expect("limited reader");
    let limit = loop {
        match reader.next_event() {
            Ok(ReaderEvent::Done) => panic!("Deflate bomb unexpectedly completed"),
            Ok(_) => {},
            Err(error) => break error,
        }
    };
    assert_eq!(limit.kind(), ErrorKind::Limit);
}

#[cfg(feature = "aes")]
#[test]
fn forward_only_reader_decodes_known_size_zipcrypto_store() {
    let password = b"known size password";
    let body = b"known-size encrypted store payload".repeat(31);
    let archive = known_size_zipcrypto_store(b"known.bin", &body, password);
    assert_eq!(u16::from_le_bytes([archive[6], archive[7]]) & 8, 0);

    assert_eq!(
        collect_with_password(OneByte::new(archive), password).expect("known-size ZipCrypto"),
        vec![(b"known.bin".to_vec(), body)]
    );
}

#[cfg(feature = "aes")]
#[test]
fn forward_only_zipcrypto_tries_candidates_and_types_failures() {
    let password = b"correct stream password";
    let body = b"candidate and integrity payload".repeat(41);
    let archive = independent_zipcrypto_store("candidates.bin", &body, password);
    let options = password_options([
        b"incorrect candidate".to_vec(),
        password.to_vec(),
        b"unused candidate".to_vec(),
    ]);
    let mut reader =
        ArchiveReader::with_options(OneByte::new(archive.clone()), &options).expect("reader");
    let mut decoded = Vec::new();
    loop {
        match reader.next_event().expect("candidate succeeds") {
            ReaderEvent::Data(data) => decoded.extend_from_slice(data),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(decoded, body);

    let wrong = collect_with_password(OneByte::new(archive.clone()), b"wrong password")
        .expect_err("wrong password");
    assert_eq!(wrong.kind(), ErrorKind::Integrity);

    let mut without_password =
        ArchiveReader::with_format(OneByte::new(archive.clone()), FormatId::Zip).unwrap();
    let missing = loop {
        match without_password.next_event() {
            Ok(ReaderEvent::Done) => panic!("encrypted ZIP completed without a password"),
            Ok(_) => {},
            Err(error) => break error,
        }
    };
    assert_eq!(missing.kind(), ErrorKind::Unsupported);

    let name = usize::from(u16::from_le_bytes([archive[26], archive[27]]));
    let extra = usize::from(u16::from_le_bytes([archive[28], archive[29]]));
    let mut tampered = archive.clone();
    tampered[30 + name + extra + 12] ^= 0x80;
    let tamper =
        collect_with_password(OneByte::new(tampered), password).expect_err("tampered ciphertext");
    assert_eq!(tamper.kind(), ErrorKind::Integrity);

    let central = find_signature(&archive, 0x0201_4b50);
    let truncated = archive[..central - 5].to_vec();
    let truncation =
        collect_with_password(OneByte::new(truncated), password).expect_err("truncated descriptor");
    assert_eq!(truncation.kind(), ErrorKind::Malformed);

    let limited = password_options([password.to_vec()])
        .with_limits(Limits::default().with_entry_bytes(Some(8)));
    let mut reader =
        ArchiveReader::with_options(OneByte::new(archive), &limited).expect("limited reader");
    let limit = loop {
        match reader.next_event() {
            Ok(ReaderEvent::Done) => panic!("oversized encrypted entry completed"),
            Ok(_) => {},
            Err(error) => break error,
        }
    };
    assert_eq!(limit.kind(), ErrorKind::Limit);
}

#[test]
fn forward_only_reader_preserves_a_descriptor_sharing_the_input_chunk() {
    let body = b"payload and descriptor in one ordinary reader buffer";
    let archive = streaming_zip(ZipMethod::Deflate, &[(b"chunk.txt", body)]);

    assert_eq!(
        collect_from(Cursor::new(archive)),
        vec![(b"chunk.txt".to_vec(), body.to_vec())]
    );
}

#[test]
fn forward_only_reader_decodes_stored_data_descriptors_without_false_signatures() {
    let marker_in_payload = [
        b"leftPK".as_slice(),
        &[7, 8, 0, 0, 0, 0, 8, 0, 0, 0, 8, 0, 0, 0],
        b"right".as_slice(),
    ]
    .concat();
    let archive = streaming_zip(
        ZipMethod::Store,
        &[
            (b"first.bin", marker_in_payload.as_slice()),
            (b"second.txt", b"second payload"),
        ],
    );

    assert_eq!(
        collect(archive),
        vec![
            (b"first.bin".to_vec(), marker_in_payload),
            (b"second.txt".to_vec(), b"second payload".to_vec()),
        ]
    );
}

#[test]
fn forward_only_reader_decodes_deflate_data_descriptors_one_byte_at_a_time() {
    let payload = b"forward-only deflate payload ".repeat(4096);
    let archive = streaming_zip(ZipMethod::Deflate, &[(b"large.txt", payload.as_slice())]);

    assert_eq!(collect(archive), vec![(b"large.txt".to_vec(), payload)]);
}

#[cfg(feature = "zstd")]
#[test]
fn forward_only_reader_decodes_zstd_data_descriptors_one_byte_at_a_time() {
    let payload = b"forward-only zstandard payload ".repeat(4096);
    let archive = streaming_zip(ZipMethod::Zstd, &[(b"large.zst", payload.as_slice())]);
    let flags = u16::from_le_bytes(archive[6..8].try_into().unwrap());
    assert_ne!(flags & 8, 0, "fixture must exercise a data descriptor");

    assert_eq!(
        collect_from(Cursor::new(archive.clone())),
        vec![(b"large.zst".to_vec(), payload.clone())]
    );
    assert_eq!(collect(archive), vec![(b"large.zst".to_vec(), payload)]);
}

#[cfg(feature = "zstd")]
#[test]
fn forward_only_reader_decodes_known_size_and_zip64_zstd() {
    let body = b"independent zstandard payload".repeat(2048);
    let known = independent_zip(zip::CompressionMethod::Zstd, "known.zst", &body);
    assert_eq!(u16::from_le_bytes(known[6..8].try_into().unwrap()) & 8, 0);
    assert_eq!(collect(known), vec![(b"known.zst".to_vec(), body.clone())]);

    let zip64 = streaming_zip_with_size_mode(
        ZipMethod::Zstd,
        &[(b"zip64.zst", b"Zstandard ZIP64 descriptor")],
        false,
    );
    assert_eq!(
        u32::from_le_bytes(zip64[18..22].try_into().unwrap()),
        u32::MAX
    );
    assert_eq!(
        collect(zip64),
        vec![(
            b"zip64.zst".to_vec(),
            b"Zstandard ZIP64 descriptor".to_vec()
        )]
    );
}

#[cfg(feature = "zstd")]
#[test]
fn forward_only_reader_preserves_a_checksum_zstd_descriptor_boundary() {
    let body = b"independent checksum-bearing Zstandard frame".repeat(4096);
    let archive = checksum_zstd_zip(b"checksum.zst", &body);

    assert_eq!(collect(archive), vec![(b"checksum.zst".to_vec(), body)]);
}

#[cfg(feature = "zstd")]
#[test]
fn forward_only_reader_accepts_unsigned_zstd_descriptor() {
    let mut archive = streaming_zip(
        ZipMethod::Zstd,
        &[(b"unsigned.zst", b"Zstandard descriptor without signature")],
    );
    let descriptor = find_signature(&archive, 0x0807_4b50);
    archive.drain(descriptor..descriptor + 4);
    let eocd = find_signature(&archive, 0x0605_4b50);
    let central_offset = u32::from_le_bytes(archive[eocd + 16..eocd + 20].try_into().unwrap()) - 4;
    archive[eocd + 16..eocd + 20].copy_from_slice(&central_offset.to_le_bytes());

    assert_eq!(
        collect(archive),
        vec![(
            b"unsigned.zst".to_vec(),
            b"Zstandard descriptor without signature".to_vec()
        )]
    );
}

#[cfg(feature = "zstd")]
#[test]
fn forward_only_zstd_rejects_malformed_integrity_and_resource_violations() {
    let body = b"bounded Zstandard payload".repeat(4096);
    let archive = streaming_zip(ZipMethod::Zstd, &[(b"bounded.zst", body.as_slice())]);
    let descriptor = find_signature(&archive, 0x0807_4b50);
    let name_length = usize::from(u16::from_le_bytes(archive[26..28].try_into().unwrap()));
    let extra_length = usize::from(u16::from_le_bytes(archive[28..30].try_into().unwrap()));
    let data_start = 30 + name_length + extra_length;

    let mut bad_crc = archive.clone();
    bad_crc[descriptor + 4] ^= 0x80;
    assert_eq!(
        first_error(bad_crc, Limits::default()),
        ErrorKind::Integrity
    );

    let mut trailing = archive.clone();
    trailing.insert(descriptor, 0);
    assert_eq!(
        first_error(trailing, Limits::default()),
        ErrorKind::Integrity
    );

    let mut truncated = archive.clone();
    truncated.remove(descriptor - 1);
    assert_eq!(
        first_error(truncated, Limits::default()),
        ErrorKind::Malformed
    );

    let mut reserved = archive.clone();
    reserved[data_start + 4] |= 0x08;
    assert_eq!(
        first_error(reserved, Limits::default()),
        ErrorKind::Malformed
    );

    let mut reserved_block = archive.clone();
    assert_eq!(reserved_block[data_start + 4], 0);
    reserved_block[data_start + 6] = (reserved_block[data_start + 6] & !0x06) | 0x06;
    assert_eq!(
        first_error(reserved_block, Limits::default()),
        ErrorKind::Malformed
    );

    assert_eq!(
        first_error(
            archive.clone(),
            Limits::safe().with_codec_memory(Some(1023))
        ),
        ErrorKind::Limit
    );
    assert_eq!(
        first_error(archive, Limits::safe().with_entry_bytes(Some(1024))),
        ErrorKind::Limit
    );
}

#[cfg(feature = "xz")]
#[test]
fn forward_only_reader_decodes_known_size_xz() {
    let body = b"independent forward-only XZ payload".repeat(4096);
    let archive = independent_zip(zip::CompressionMethod::Xz, "known.xz", &body);
    assert_eq!(u16::from_le_bytes(archive[6..8].try_into().unwrap()) & 8, 0);

    assert_eq!(
        collect_from(Cursor::new(archive.clone())),
        vec![(b"known.xz".to_vec(), body.clone())]
    );
    assert_eq!(collect(archive), vec![(b"known.xz".to_vec(), body)]);

    let empty = independent_zip(zip::CompressionMethod::Xz, "empty.xz", b"");
    assert_eq!(collect(empty), vec![(b"empty.xz".to_vec(), Vec::new())]);
}

#[cfg(feature = "xz")]
#[test]
fn forward_only_reader_decodes_known_size_lzma_one_byte_at_a_time() {
    let fixture = include_bytes!("fixtures/zip/python-lzma/lzma-basic.zip").to_vec();
    let big = b"the quick brown fox jumps over the lazy dog\n".repeat(200);

    assert_eq!(
        collect_from(OneByte::new(fixture)),
        vec![
            (b"readme.txt".to_vec(), b"hello lzma world\n".to_vec()),
            (b"sub/big.txt".to_vec(), big),
            (b"sub/empty.txt".to_vec(), Vec::new()),
        ]
    );
}

#[cfg(feature = "ppmd")]
#[test]
fn forward_only_reader_decodes_ppmd_descriptor_one_byte_at_a_time() {
    let body = b"forward-only PPMd descriptor payload\n".repeat(4096);
    let signed = streaming_zip(ZipMethod::Ppmd8, &[(b"descriptor.ppmd", &body)]);

    assert_eq!(
        collect_from(OneByte::new(signed.clone())),
        vec![(b"descriptor.ppmd".to_vec(), body.clone())]
    );
    assert_eq!(
        collect_from(OneByte::new(signed_descriptor_zip_to_unsigned(signed,))),
        vec![(b"descriptor.ppmd".to_vec(), body.clone())]
    );

    let zip64 = signed_descriptor_zip_to_zip64(streaming_zip(
        ZipMethod::Ppmd8,
        &[(b"zip64.ppmd", b"PPMd ZIP64 descriptor")],
    ));
    assert_eq!(
        collect_from(OneByte::new(zip64.clone())),
        vec![(b"zip64.ppmd".to_vec(), b"PPMd ZIP64 descriptor".to_vec())]
    );
    assert_eq!(
        collect_from(OneByte::new(signed_descriptor_zip_to_unsigned(zip64))),
        vec![(b"zip64.ppmd".to_vec(), b"PPMd ZIP64 descriptor".to_vec())]
    );

    let second = b"second PPMd member after an exact descriptor".repeat(1024);
    let multiple = streaming_zip(
        ZipMethod::Ppmd8,
        &[
            (b"first.ppmd", body.as_slice()),
            (b"second.ppmd", second.as_slice()),
            (b"empty.ppmd", b""),
        ],
    );
    assert_eq!(
        collect_from(Cursor::new(multiple)),
        vec![
            (b"first.ppmd".to_vec(), body),
            (b"second.ppmd".to_vec(), second),
            (b"empty.ppmd".to_vec(), Vec::new()),
        ]
    );
}

#[cfg(feature = "ppmd")]
#[test]
fn forward_only_reader_decodes_known_size_and_independent_ppmd() {
    let body = b"known-size PPMd payload".repeat(4096);
    let known =
        descriptor_zip_to_known_size(streaming_zip(ZipMethod::Ppmd8, &[(b"known.ppmd", &body)]));
    assert_eq!(
        collect_from(OneByte::new(known)),
        vec![(b"known.ppmd".to_vec(), body.clone())]
    );

    let independent = independent_zip(zip::CompressionMethod::Ppmd, "independent.ppmd", &body);
    assert_eq!(
        collect_from(OneByte::new(independent)),
        vec![(b"independent.ppmd".to_vec(), body)]
    );
}

#[cfg(feature = "ppmd")]
#[test]
fn forward_only_ppmd_types_integrity_truncation_and_limits() {
    let body = b"bounded forward-only PPMd payload".repeat(4096);
    let archive = streaming_zip(ZipMethod::Ppmd8, &[(b"bounded.ppmd", &body)]);
    let descriptor = find_signature(&archive, 0x0807_4b50);
    let central = find_signature(&archive, 0x0201_4b50);
    let name = usize::from(u16::from_le_bytes(archive[26..28].try_into().unwrap()));
    let extra = usize::from(u16::from_le_bytes(archive[28..30].try_into().unwrap()));
    let payload = 30 + name + extra;

    let mut bad_parameters = archive.clone();
    bad_parameters[payload..payload + 2].fill(0);
    assert_eq!(
        first_error(bad_parameters, Limits::default()),
        ErrorKind::Malformed
    );

    let mut bad_range = archive.clone();
    bad_range[payload + 2..payload + 6].fill(0xff);
    assert_eq!(
        first_error(bad_range, Limits::default()),
        ErrorKind::Malformed
    );

    for offset in [4, 8, 12] {
        let mut mismatched = archive.clone();
        mismatched[descriptor + offset] ^= 0x80;
        assert_eq!(
            first_error(mismatched, Limits::default()),
            ErrorKind::Integrity,
            "descriptor field at +{offset}"
        );
    }

    assert_eq!(
        first_error(archive[..central - 1].to_vec(), Limits::default()),
        ErrorKind::Malformed
    );
    assert_eq!(
        first_error(
            archive.clone(),
            Limits::default().with_codec_memory(Some(1024 * 1024)),
        ),
        ErrorKind::Limit
    );
    assert_eq!(
        first_error(archive, Limits::default().with_decoded_total(Some(1024)),),
        ErrorKind::Limit
    );
}

#[cfg(feature = "xz")]
#[test]
fn forward_only_lzma_decodes_signed_unsigned_and_zip64_descriptors() {
    let body = b"forward-only LZMA descriptor payload\n".repeat(4096);
    let signed = streaming_zip(ZipMethod::Lzma, &[(b"signed.lzma", &body)]);
    assert_ne!(u16::from_le_bytes(signed[6..8].try_into().unwrap()) & 8, 0);
    assert_eq!(
        collect_from(Cursor::new(signed.clone())),
        vec![(b"signed.lzma".to_vec(), body.clone())]
    );

    let mut unsigned = signed;
    let descriptor = find_signature(&unsigned, 0x0807_4b50);
    unsigned.drain(descriptor..descriptor + 4);
    let eocd = find_signature(&unsigned, 0x0605_4b50);
    let central = u32::from_le_bytes(unsigned[eocd + 16..eocd + 20].try_into().unwrap()) - 4;
    unsigned[eocd + 16..eocd + 20].copy_from_slice(&central.to_le_bytes());
    assert_eq!(
        collect_from(OneByte::new(unsigned)),
        vec![(b"signed.lzma".to_vec(), body.clone())]
    );

    let zip64 = signed_descriptor_zip_to_zip64(streaming_zip(
        ZipMethod::Lzma,
        &[(b"zip64.lzma", b"LZMA ZIP64 descriptor")],
    ));
    assert_eq!(
        collect_from(OneByte::new(zip64.clone())),
        vec![(b"zip64.lzma".to_vec(), b"LZMA ZIP64 descriptor".to_vec())]
    );
    assert_eq!(
        collect_from(OneByte::new(signed_descriptor_zip_to_unsigned(zip64))),
        vec![(b"zip64.lzma".to_vec(), b"LZMA ZIP64 descriptor".to_vec())]
    );

    let second = b"second LZMA member after an exact descriptor".repeat(1024);
    let multiple = streaming_zip(
        ZipMethod::Lzma,
        &[
            (b"first.lzma", body.as_slice()),
            (b"second.lzma", second.as_slice()),
            (b"empty.lzma", b""),
        ],
    );
    assert_eq!(
        collect_from(Cursor::new(multiple)),
        vec![
            (b"first.lzma".to_vec(), body),
            (b"second.lzma".to_vec(), second),
            (b"empty.lzma".to_vec(), Vec::new()),
        ]
    );
}

#[cfg(feature = "xz")]
#[test]
fn forward_only_lzma_descriptor_types_integrity_truncation_and_limits() {
    let body = b"bounded LZMA descriptor payload".repeat(4096);
    let archive = streaming_zip(ZipMethod::Lzma, &[(b"bounded-descriptor.lzma", &body)]);
    let descriptor = find_signature(&archive, 0x0807_4b50);
    let central = find_signature(&archive, 0x0201_4b50);

    let mut bad_crc = archive.clone();
    bad_crc[descriptor + 4] ^= 0x80;
    assert_eq!(
        first_error(bad_crc, Limits::default()),
        ErrorKind::Integrity
    );

    let mut bad_compressed = archive.clone();
    bad_compressed[descriptor + 8] ^= 0x80;
    assert_eq!(
        first_error(bad_compressed, Limits::default()),
        ErrorKind::Integrity
    );

    let mut bad_uncompressed = archive.clone();
    bad_uncompressed[descriptor + 12] ^= 0x80;
    assert_eq!(
        first_error(bad_uncompressed, Limits::default()),
        ErrorKind::Integrity
    );

    assert_eq!(
        first_error(archive[..central - 1].to_vec(), Limits::default()),
        ErrorKind::Malformed
    );
    assert_eq!(
        first_error(
            archive.clone(),
            Limits::default().with_decoded_total(Some(1024)),
        ),
        ErrorKind::Limit
    );

    let mut no_end_marker = archive;
    let flags = u16::from_le_bytes(no_end_marker[6..8].try_into().unwrap()) & !0x0002;
    no_end_marker[6..8].copy_from_slice(&flags.to_le_bytes());
    assert_eq!(
        first_error(no_end_marker, Limits::default()),
        ErrorKind::Unsupported
    );
}

#[cfg(feature = "xz")]
#[test]
fn forward_only_lzma_known_sizes_type_integrity_truncation_and_limits() {
    let body = b"bounded forward-only LZMA payload\n".repeat(4096);
    let descriptor = streaming_zip(ZipMethod::Lzma, &[(b"bounded.lzma", &body)]);
    let archive = descriptor_zip_to_known_size(descriptor);
    assert_eq!(
        collect_from(Cursor::new(archive.clone())),
        vec![(b"bounded.lzma".to_vec(), body.clone())]
    );

    let name = usize::from(u16::from_le_bytes(archive[26..28].try_into().unwrap()));
    let extra = usize::from(u16::from_le_bytes(archive[28..30].try_into().unwrap()));
    let payload = 30 + name + extra;
    let central = find_signature(&archive, 0x0201_4b50);

    let mut no_eos_flag = archive.clone();
    let flags = u16::from_le_bytes(no_eos_flag[6..8].try_into().unwrap()) & !0x0002;
    no_eos_flag[6..8].copy_from_slice(&flags.to_le_bytes());
    let flags =
        u16::from_le_bytes(no_eos_flag[central + 8..central + 10].try_into().unwrap()) & !0x0002;
    no_eos_flag[central + 8..central + 10].copy_from_slice(&flags.to_le_bytes());
    assert_eq!(
        collect(no_eos_flag),
        vec![(b"bounded.lzma".to_vec(), body.clone())]
    );

    let mut bad_crc = archive.clone();
    bad_crc[14] ^= 0x80;
    assert_eq!(
        first_error(bad_crc, Limits::default()),
        ErrorKind::Integrity
    );

    let mut bad_size = archive.clone();
    bad_size[22] ^= 0x80;
    assert_eq!(
        first_error(bad_size, Limits::default()),
        ErrorKind::Integrity
    );

    let mut bad_properties = archive.clone();
    bad_properties[payload + 2] = 4;
    assert_eq!(
        first_error(bad_properties, Limits::default()),
        ErrorKind::Malformed
    );

    let mut large_dictionary = archive.clone();
    large_dictionary[payload + 5..payload + 9]
        .copy_from_slice(&(64_u32 * 1024 * 1024).to_le_bytes());
    assert_eq!(
        first_error(
            large_dictionary,
            Limits::default().with_codec_memory(Some(1024 * 1024)),
        ),
        ErrorKind::Limit
    );

    assert_eq!(
        first_error(
            archive.clone(),
            Limits::default().with_decoded_total(Some(1024)),
        ),
        ErrorKind::Limit
    );
    assert_eq!(
        first_error(archive[..central - 1].to_vec(), Limits::default()),
        ErrorKind::Malformed
    );
}

#[cfg(feature = "xz")]
#[test]
fn forward_only_reader_decodes_signed_xz_descriptor() {
    let payload = b"signed XZ descriptor payload".repeat(2048);
    let archive = streaming_zip(ZipMethod::Xz, &[(b"descriptor.xz", &payload)]);
    assert_ne!(u16::from_le_bytes(archive[6..8].try_into().unwrap()) & 8, 0);

    assert_eq!(
        collect_from(Cursor::new(archive.clone())),
        vec![(b"descriptor.xz".to_vec(), payload.clone())]
    );
    assert_eq!(collect(archive), vec![(b"descriptor.xz".to_vec(), payload)]);

    let zip64 = streaming_zip_with_size_mode(
        ZipMethod::Xz,
        &[(b"zip64.xz", b"XZ ZIP64 descriptor")],
        false,
    );
    assert_eq!(
        collect(zip64),
        vec![(b"zip64.xz".to_vec(), b"XZ ZIP64 descriptor".to_vec())]
    );

    let empty = streaming_zip(ZipMethod::Xz, &[(b"empty.xz", b"")]);
    assert_eq!(collect(empty), vec![(b"empty.xz".to_vec(), Vec::new())]);
}

#[cfg(feature = "xz")]
#[test]
fn forward_only_xz_accepts_aligned_padding_and_rejects_unsigned_descriptors() {
    let payload = b"XZ stream padding".repeat(1024);
    let archive = streaming_zip(ZipMethod::Xz, &[(b"padding.xz", &payload)]);
    let descriptor = find_signature(&archive, 0x0807_4b50);
    let mut padded = archive.clone();
    padded.splice(descriptor..descriptor, [0_u8; 4]);
    let descriptor = descriptor + 4;
    let compressed =
        u32::from_le_bytes(padded[descriptor + 8..descriptor + 12].try_into().unwrap());
    padded[descriptor + 8..descriptor + 12].copy_from_slice(&(compressed + 4).to_le_bytes());
    let central = find_signature(&padded, 0x0201_4b50);
    padded[central + 20..central + 24].copy_from_slice(&(compressed + 4).to_le_bytes());
    let eocd = find_signature(&padded, 0x0605_4b50);
    padded[eocd + 16..eocd + 20].copy_from_slice(&u32::try_from(central).unwrap().to_le_bytes());
    assert_eq!(collect(padded), vec![(b"padding.xz".to_vec(), payload)]);

    let mut unsigned = archive;
    let descriptor = find_signature(&unsigned, 0x0807_4b50);
    unsigned.drain(descriptor..descriptor + 4);
    assert_eq!(
        first_error(unsigned, Limits::default()),
        ErrorKind::Unsupported
    );
}

#[cfg(feature = "xz")]
#[test]
fn forward_only_xz_descriptor_rejects_integrity_truncation_and_resource_violations() {
    let payload = b"bounded descriptor XZ payload".repeat(4096);
    let archive = streaming_zip(ZipMethod::Xz, &[(b"bounded.xz", &payload)]);
    let descriptor = find_signature(&archive, 0x0807_4b50);

    let mut bad_crc = archive.clone();
    bad_crc[descriptor + 4] ^= 0x80;
    assert_eq!(
        first_error(bad_crc, Limits::default()),
        ErrorKind::Integrity
    );

    let mut bad_compressed = archive.clone();
    let compressed = u32::from_le_bytes(
        bad_compressed[descriptor + 8..descriptor + 12]
            .try_into()
            .unwrap(),
    );
    bad_compressed[descriptor + 8..descriptor + 12]
        .copy_from_slice(&(compressed + 1).to_le_bytes());
    assert_eq!(
        first_error(bad_compressed, Limits::default()),
        ErrorKind::Integrity
    );

    let mut bad_size = archive.clone();
    let size = u32::from_le_bytes(
        bad_size[descriptor + 12..descriptor + 16]
            .try_into()
            .unwrap(),
    );
    bad_size[descriptor + 12..descriptor + 16].copy_from_slice(&(size + 1).to_le_bytes());
    assert_eq!(
        first_error(bad_size, Limits::default()),
        ErrorKind::Integrity
    );

    let mut truncated = archive.clone();
    truncated.remove(descriptor - 1);
    assert_eq!(
        first_error(truncated, Limits::default()),
        ErrorKind::Malformed
    );

    assert_eq!(
        first_error(
            archive.clone(),
            Limits::safe().with_codec_memory(Some(1024))
        ),
        ErrorKind::Limit
    );
    assert_eq!(
        first_error(archive, Limits::safe().with_entry_bytes(Some(1024))),
        ErrorKind::Limit
    );
}

#[cfg(feature = "xz")]
#[test]
fn forward_only_xz_rejects_integrity_truncation_and_resource_violations() {
    let body = b"bounded XZ payload".repeat(4096);
    let archive = independent_zip(zip::CompressionMethod::Xz, "bounded.xz", &body);

    let mut bad_crc = archive.clone();
    bad_crc[14] ^= 0x80;
    assert_eq!(
        first_error(bad_crc, Limits::default()),
        ErrorKind::Integrity
    );

    let mut bad_size = archive.clone();
    let declared = u32::from_le_bytes(bad_size[22..26].try_into().unwrap()) + 1;
    bad_size[22..26].copy_from_slice(&declared.to_le_bytes());
    assert_eq!(
        first_error(bad_size, Limits::default()),
        ErrorKind::Integrity
    );

    let name_length = usize::from(u16::from_le_bytes(archive[26..28].try_into().unwrap()));
    let extra_length = usize::from(u16::from_le_bytes(archive[28..30].try_into().unwrap()));
    let compressed = u32::from_le_bytes(archive[18..22].try_into().unwrap());
    let data_end = 30 + name_length + extra_length + usize::try_from(compressed).unwrap();
    let central = find_signature(&archive, 0x0201_4b50);
    assert_eq!(data_end, central);

    let mut trailing = archive.clone();
    trailing.insert(data_end, 0);
    trailing[18..22].copy_from_slice(&(compressed + 1).to_le_bytes());
    let shifted_central = central + 1;
    trailing[shifted_central + 20..shifted_central + 24]
        .copy_from_slice(&(compressed + 1).to_le_bytes());
    let shifted_eocd = find_signature(&trailing, 0x0605_4b50);
    trailing[shifted_eocd + 16..shifted_eocd + 20]
        .copy_from_slice(&u32::try_from(shifted_central).unwrap().to_le_bytes());
    assert_eq!(
        first_error(trailing, Limits::default()),
        ErrorKind::Malformed
    );

    let mut truncated = archive.clone();
    truncated.remove(data_end - 1);
    truncated[18..22].copy_from_slice(&(compressed - 1).to_le_bytes());
    let shifted_central = central - 1;
    truncated[shifted_central + 20..shifted_central + 24]
        .copy_from_slice(&(compressed - 1).to_le_bytes());
    let shifted_eocd = find_signature(&truncated, 0x0605_4b50);
    truncated[shifted_eocd + 16..shifted_eocd + 20]
        .copy_from_slice(&u32::try_from(shifted_central).unwrap().to_le_bytes());
    assert_eq!(
        first_error(truncated, Limits::default()),
        ErrorKind::Malformed
    );

    assert_eq!(
        first_error(
            archive.clone(),
            Limits::safe().with_codec_memory(Some(1024))
        ),
        ErrorKind::Limit
    );
    assert_eq!(
        first_error(archive, Limits::safe().with_entry_bytes(Some(1024))),
        ErrorKind::Limit
    );
}

#[cfg(feature = "gzip")]
#[test]
fn forward_only_reader_decodes_known_size_deflate64() {
    let body = (0_u8..=u8::MAX).cycle().take(150_000).collect::<Vec<_>>();
    let archive = deflate64_zip(b"deflate64.bin", &body);

    assert_eq!(
        collect_from(Cursor::new(archive)),
        vec![(b"deflate64.bin".to_vec(), body)]
    );

    let fragmented = b"fragmented Deflate64 input".repeat(64);
    assert_eq!(
        collect(deflate64_zip(b"fragmented.d64", &fragmented)),
        vec![(b"fragmented.d64".to_vec(), fragmented)]
    );
}

#[cfg(feature = "gzip")]
#[test]
fn forward_only_deflate64_rejects_integrity_truncation_and_resource_violations() {
    let body = b"bounded Deflate64 payload".repeat(4096);
    let archive = deflate64_zip(b"bounded.d64", &body);

    let mut bad_crc = archive.clone();
    bad_crc[14] ^= 0x80;
    assert_eq!(
        first_error(bad_crc, Limits::default()),
        ErrorKind::Integrity
    );

    let mut bad_size = archive.clone();
    let declared = u32::from_le_bytes(bad_size[22..26].try_into().unwrap()) + 1;
    bad_size[22..26].copy_from_slice(&declared.to_le_bytes());
    assert_eq!(
        first_error(bad_size, Limits::default()),
        ErrorKind::Integrity
    );

    let name_length = usize::from(u16::from_le_bytes(archive[26..28].try_into().unwrap()));
    let compressed = u32::from_le_bytes(archive[18..22].try_into().unwrap());
    let data_end = 30 + name_length + usize::try_from(compressed).unwrap();
    let central = find_signature(&archive, 0x0201_4b50);
    assert_eq!(data_end, central);

    let mut trailing = archive.clone();
    trailing.insert(data_end, 0);
    trailing[18..22].copy_from_slice(&(compressed + 1).to_le_bytes());
    let shifted_central = central + 1;
    trailing[shifted_central + 20..shifted_central + 24]
        .copy_from_slice(&(compressed + 1).to_le_bytes());
    let shifted_eocd = find_signature(&trailing, 0x0605_4b50);
    trailing[shifted_eocd + 16..shifted_eocd + 20]
        .copy_from_slice(&u32::try_from(shifted_central).unwrap().to_le_bytes());
    assert_eq!(
        first_error(trailing, Limits::default()),
        ErrorKind::Integrity
    );

    let mut truncated = archive.clone();
    truncated.remove(data_end - 1);
    truncated[18..22].copy_from_slice(&(compressed - 1).to_le_bytes());
    let shifted_central = central - 1;
    truncated[shifted_central + 20..shifted_central + 24]
        .copy_from_slice(&(compressed - 1).to_le_bytes());
    let shifted_eocd = find_signature(&truncated, 0x0605_4b50);
    truncated[shifted_eocd + 16..shifted_eocd + 20]
        .copy_from_slice(&u32::try_from(shifted_central).unwrap().to_le_bytes());
    assert_eq!(
        first_error(truncated, Limits::default()),
        ErrorKind::Malformed
    );

    assert_eq!(
        first_error(
            archive.clone(),
            Limits::safe().with_codec_memory(Some(1024))
        ),
        ErrorKind::Limit
    );
    assert_eq!(
        first_error(archive, Limits::safe().with_entry_bytes(Some(1024))),
        ErrorKind::Limit
    );
}

#[cfg(feature = "gzip")]
#[test]
fn forward_only_deflate64_accepts_signed_and_unsigned_descriptors() {
    let body = b"descriptor Deflate64 payload".repeat(4096);
    for signed in [true, false] {
        assert_eq!(
            collect(deflate64_descriptor_zip(b"descriptor.d64", &body, signed)),
            vec![(b"descriptor.d64".to_vec(), body.clone())]
        );
    }

    let (compressed, body) = official_wide_deflate64_member();
    let archive = with_deflate64_descriptor(
        deflate64_zip_with_compressed(b"wide-window.bin", &body, &compressed),
        true,
    );
    assert_eq!(
        collect_from(Cursor::new(archive)),
        vec![(b"wide-window.bin".to_vec(), body)]
    );
}

#[cfg(feature = "gzip")]
#[test]
fn forward_only_deflate64_accepts_signed_and_unsigned_zip64_descriptors() {
    let body = b"ZIP64 descriptor Deflate64 payload".repeat(1024);
    for signed in [true, false] {
        let archive = deflate64_zip64_descriptor_zip(b"zip64.d64", &body, signed);
        assert_eq!(
            u32::from_le_bytes(archive[18..22].try_into().unwrap()),
            u32::MAX
        );
        assert_eq!(
            collect_from(Cursor::new(archive)),
            vec![(b"zip64.d64".to_vec(), body.clone())]
        );
    }
}

#[cfg(feature = "gzip")]
#[test]
fn forward_only_deflate64_descriptor_rejects_mismatch_truncation_and_bombs() {
    let body = b"bounded descriptor Deflate64 payload".repeat(4096);
    let archive = deflate64_descriptor_zip(b"bounded.d64", &body, true);
    let descriptor = find_signature(&archive, 0x0807_4b50);

    for offset in [descriptor + 4, descriptor + 8, descriptor + 12] {
        let mut mismatched = archive.clone();
        mismatched[offset] ^= 0x80;
        assert_eq!(
            first_error(mismatched, Limits::default()),
            ErrorKind::Integrity
        );
    }

    assert_eq!(
        first_error(archive[..descriptor + 10].to_vec(), Limits::default()),
        ErrorKind::Malformed
    );
    assert_eq!(
        first_error(
            archive,
            Limits::safe().with_entry_bytes(Some(body.len() as u64 - 1))
        ),
        ErrorKind::Limit
    );
}

#[cfg(not(feature = "gzip"))]
#[test]
fn forward_only_deflate64_requires_the_gzip_feature() {
    let mut archive = streaming_zip(ZipMethod::Store, &[(b"disabled.d64", b"payload")]);
    archive[8..10].copy_from_slice(&9_u16.to_le_bytes());

    assert_eq!(
        first_error(archive, Limits::default()),
        ErrorKind::Unsupported
    );
}

#[test]
fn forward_only_reader_decodes_seek_patched_store_and_deflate_members() {
    for method in [
        zip::CompressionMethod::Stored,
        zip::CompressionMethod::Deflated,
    ] {
        let archive = independent_zip(method, "independent.txt", b"independent payload");
        assert_eq!(u16::from_le_bytes([archive[6], archive[7]]) & 0x0008, 0);
        assert_eq!(
            collect(archive),
            vec![(b"independent.txt".to_vec(), b"independent payload".to_vec())]
        );
    }
}

#[test]
fn forward_only_reader_accepts_unsigned_deflate_descriptor() {
    let mut archive = streaming_zip(
        ZipMethod::Deflate,
        &[(b"unsigned.txt", b"descriptor without optional signature")],
    );
    let descriptor = find_signature(&archive, 0x0807_4b50);
    archive.drain(descriptor..descriptor + 4);
    let eocd = find_signature(&archive, 0x0605_4b50);
    let central_offset = u32::from_le_bytes(archive[eocd + 16..eocd + 20].try_into().unwrap()) - 4;
    archive[eocd + 16..eocd + 20].copy_from_slice(&central_offset.to_le_bytes());

    assert_eq!(
        collect(archive),
        vec![(
            b"unsigned.txt".to_vec(),
            b"descriptor without optional signature".to_vec()
        )]
    );
}

#[test]
fn forward_only_reader_decodes_zip64_store_and_deflate_descriptors() {
    for method in [ZipMethod::Store, ZipMethod::Deflate] {
        let archive = streaming_zip_with_size_mode(
            method,
            &[(b"zip64.txt", b"small payload in a ZIP64 descriptor")],
            false,
        );
        assert_eq!(
            u32::from_le_bytes(archive[18..22].try_into().unwrap()),
            u32::MAX
        );
        assert_eq!(
            collect(archive),
            vec![(
                b"zip64.txt".to_vec(),
                b"small payload in a ZIP64 descriptor".to_vec()
            )]
        );
    }
}

#[cfg(feature = "bzip2")]
#[test]
fn forward_only_reader_decodes_bzip2_with_and_without_data_descriptors() {
    let payload = b"forward-only bzip2 payload".repeat(2048);
    let streaming = streaming_zip(ZipMethod::Bzip2, &[(b"stream.bz2", payload.as_slice())]);
    assert_eq!(
        collect(streaming),
        vec![(b"stream.bz2".to_vec(), payload.clone())]
    );

    let patched = independent_zip(
        zip::CompressionMethod::Bzip2,
        "patched.bz2",
        payload.as_slice(),
    );
    assert_eq!(collect(patched), vec![(b"patched.bz2".to_vec(), payload)]);
}

#[test]
fn forward_only_reader_surfaces_the_eocd_archive_comment() {
    let mut writer =
        ArchiveWriter::with_zip_method(Vec::new(), ZipMethod::Store, Limits::default());
    writer
        .set_archive_metadata(
            &ArchiveMetadata::new().with_comment(b"forward-only comment".to_vec()),
        )
        .unwrap();
    let archive = writer.finish().unwrap();
    let mut reader = ArchiveReader::new(OneByte::new(archive));
    loop {
        match reader.next_event().unwrap() {
            ReaderEvent::ArchiveMetadata(metadata) => {
                assert_eq!(metadata.comment(), Some(b"forward-only comment".as_slice()));
                break;
            },
            ReaderEvent::Done => panic!("archive comment was not surfaced"),
            _ => {},
        }
    }
}

#[test]
fn forward_only_reader_rejects_crc_count_truncation_and_resource_violations() {
    let archive = streaming_zip(
        ZipMethod::Deflate,
        &[(
            b"bounded.txt",
            b"payload larger than the configured entry limit",
        )],
    );
    assert_eq!(
        first_error(archive.clone(), Limits::safe().with_entry_bytes(Some(4))),
        ErrorKind::Limit
    );
    assert_eq!(
        first_error(archive.clone(), Limits::safe().with_path_bytes(Some(4))),
        ErrorKind::Limit
    );

    let mut bad_crc = archive.clone();
    let descriptor = find_signature(&bad_crc, 0x0807_4b50);
    bad_crc[descriptor + 4] ^= 0x80;
    assert_eq!(
        first_error(bad_crc, Limits::default()),
        ErrorKind::Integrity
    );

    let mut bad_count = archive.clone();
    let eocd = find_signature(&bad_count, 0x0605_4b50);
    bad_count[eocd + 8..eocd + 12].copy_from_slice(&[2, 0, 2, 0]);
    assert_eq!(
        first_error(bad_count, Limits::default()),
        ErrorKind::Integrity
    );

    for end in [
        3,
        29,
        descriptor.saturating_sub(1),
        descriptor + 15,
        eocd + 21,
    ] {
        assert_eq!(
            first_error(archive[..end].to_vec(), Limits::default()),
            ErrorKind::Malformed
        );
    }
}

#[cfg(feature = "async")]
#[test]
fn futures_reader_uses_the_same_forward_only_zip_state_machine() {
    futures_lite::future::block_on(async {
        let payload = b"futures ZIP payload".repeat(1024);
        let archive = streaming_zip(ZipMethod::Deflate, &[(b"futures.txt", payload.as_slice())]);
        let mut reader = AsyncArchiveReader::new(AsyncOneByte {
            bytes: archive,
            position: 0,
        });
        let mut decoded = Vec::new();
        loop {
            match reader.next_event().await.unwrap() {
                ReaderEvent::Data(data) => decoded.extend_from_slice(data),
                ReaderEvent::Done => break,
                _ => {},
            }
        }
        assert_eq!(decoded, payload);
    });
}

#[cfg(all(feature = "async", feature = "gzip"))]
#[test]
fn futures_reader_streams_deflate64_descriptors_one_byte_at_a_time() {
    futures_lite::future::block_on(async {
        let payload = b"futures Deflate64 descriptor payload".repeat(1024);
        let archive = deflate64_descriptor_zip(b"futures.d64", &payload, true);
        let mut reader = AsyncArchiveReader::new(AsyncOneByte {
            bytes: archive,
            position: 0,
        });
        let mut decoded = Vec::new();
        loop {
            match reader.next_event().await.unwrap() {
                ReaderEvent::Data(data) => decoded.extend_from_slice(data),
                ReaderEvent::Done => break,
                _ => {},
            }
        }
        assert_eq!(decoded, payload);
    });
}

#[cfg(all(feature = "async", feature = "zstd"))]
#[test]
fn futures_reader_streams_zstd_descriptors_one_byte_at_a_time() {
    futures_lite::future::block_on(async {
        let payload = b"futures Zstandard ZIP payload".repeat(1024);
        let archive = streaming_zip(ZipMethod::Zstd, &[(b"futures.zst", payload.as_slice())]);
        let mut reader = AsyncArchiveReader::new(AsyncOneByte {
            bytes: archive,
            position: 0,
        });
        let mut decoded = Vec::new();
        loop {
            match reader.next_event().await.unwrap() {
                ReaderEvent::Data(data) => decoded.extend_from_slice(data),
                ReaderEvent::Done => break,
                _ => {},
            }
        }
        assert_eq!(decoded, payload);
    });
}

#[cfg(all(feature = "async", feature = "xz"))]
#[test]
fn futures_reader_streams_signed_xz_descriptor_one_byte_at_a_time() {
    futures_lite::future::block_on(async {
        let payload = b"futures XZ ZIP payload".repeat(1024);
        let archive = streaming_zip(ZipMethod::Xz, &[(b"futures.xz", &payload)]);
        let mut reader = AsyncArchiveReader::new(AsyncOneByte {
            bytes: archive,
            position: 0,
        });
        let mut decoded = Vec::new();
        loop {
            match reader.next_event().await.unwrap() {
                ReaderEvent::Data(data) => decoded.extend_from_slice(data),
                ReaderEvent::Done => break,
                _ => {},
            }
        }
        assert_eq!(decoded, payload);
    });
}

#[cfg(all(feature = "async", feature = "xz"))]
#[test]
fn futures_reader_streams_lzma_descriptor_one_byte_at_a_time() {
    futures_lite::future::block_on(async {
        let payload = b"futures LZMA descriptor payload".repeat(1024);
        let archive = streaming_zip(ZipMethod::Lzma, &[(b"futures.lzma", &payload)]);
        let mut reader = AsyncArchiveReader::new(AsyncOneByte {
            bytes: archive,
            position: 0,
        });
        let mut decoded = Vec::new();
        loop {
            match reader.next_event().await.unwrap() {
                ReaderEvent::Data(data) => decoded.extend_from_slice(data),
                ReaderEvent::Done => break,
                _ => {},
            }
        }
        assert_eq!(decoded, payload);
    });
}

#[cfg(all(feature = "async", feature = "ppmd"))]
#[test]
fn futures_reader_streams_ppmd_descriptor_one_byte_at_a_time() {
    futures_lite::future::block_on(async {
        let payload = b"futures PPMd descriptor payload".repeat(1024);
        let archive = streaming_zip(ZipMethod::Ppmd8, &[(b"futures.ppmd", &payload)]);
        let mut reader = AsyncArchiveReader::new(AsyncOneByte {
            bytes: archive,
            position: 0,
        });
        let mut decoded = Vec::new();
        loop {
            match reader.next_event().await.unwrap() {
                ReaderEvent::Data(data) => decoded.extend_from_slice(data),
                ReaderEvent::Done => break,
                _ => {},
            }
        }
        assert_eq!(decoded, payload);
    });
}

#[cfg(all(feature = "async", feature = "aes"))]
#[test]
fn futures_reader_streams_zipcrypto_descriptors_one_byte_at_a_time() {
    futures_lite::future::block_on(async {
        let password = b"futures encrypted password";
        let payload = b"futures ZipCrypto ZIP payload".repeat(1024);
        let options = password_options([password.to_vec()]);
        for method in [
            zip::CompressionMethod::Stored,
            zip::CompressionMethod::Deflated,
        ] {
            let archive = independent_zipcrypto("futures.enc", &payload, password, method);
            let mut reader = AsyncArchiveReader::with_options(
                AsyncOneByte {
                    bytes: archive,
                    position: 0,
                },
                &options,
            )
            .expect("async encrypted reader");
            let mut decoded = Vec::new();
            loop {
                match reader.next_event().await.unwrap() {
                    ReaderEvent::Data(data) => decoded.extend_from_slice(data),
                    ReaderEvent::Done => break,
                    _ => {},
                }
            }
            assert_eq!(decoded, payload, "{method:?}");
        }
    });
}

#[cfg(all(feature = "async", feature = "aes", feature = "gzip"))]
#[test]
fn futures_reader_streams_zipcrypto_deflate64_descriptor_one_byte_at_a_time() {
    futures_lite::future::block_on(async {
        let password = b"futures Deflate64 ZipCrypto password";
        let payload = b"futures ZipCrypto Deflate64 payload".repeat(1024);
        let compressed = stored_deflate64(&payload);
        let archive = zipcrypto_deflate64_descriptor(
            b"futures.d64",
            &payload,
            &compressed,
            password,
            true,
            false,
        );
        let options = password_options([password.to_vec()]);
        let mut reader = AsyncArchiveReader::with_options(
            AsyncOneByte {
                bytes: archive,
                position: 0,
            },
            &options,
        )
        .expect("futures ZipCrypto Deflate64 reader");
        let mut decoded = Vec::new();
        loop {
            match reader.next_event().await.unwrap() {
                ReaderEvent::Data(data) => decoded.extend_from_slice(data),
                ReaderEvent::Done => break,
                _ => {},
            }
        }
        assert_eq!(decoded, payload);
    });
}

#[cfg(all(
    feature = "async",
    feature = "aes",
    feature = "bzip2",
    feature = "zstd",
    feature = "xz"
))]
#[test]
fn futures_reader_streams_zipcrypto_pipeline_descriptors_one_byte_at_a_time() {
    futures_lite::future::block_on(async {
        let password = b"futures encrypted pipeline password";
        let payload = b"futures ZipCrypto pipeline payload".repeat(1024);
        let options = password_options([password.to_vec()]);
        for method in [
            ZipMethod::Bzip2,
            ZipMethod::Lzma,
            ZipMethod::Ppmd8,
            ZipMethod::Zstd,
            ZipMethod::Xz,
        ] {
            let archive = streaming_zipcrypto(method, b"futures.pipeline", &payload, password);
            let mut reader = AsyncArchiveReader::with_options(
                AsyncOneByte {
                    bytes: archive,
                    position: 0,
                },
                &options,
            )
            .expect("async encrypted pipeline reader");
            let mut decoded = Vec::new();
            loop {
                match reader.next_event().await.unwrap() {
                    ReaderEvent::Data(data) => decoded.extend_from_slice(data),
                    ReaderEvent::Done => break,
                    _ => {},
                }
            }
            assert_eq!(decoded, payload, "{method:?}");
        }
    });
}

#[cfg(all(
    feature = "async",
    feature = "aes",
    feature = "bzip2",
    feature = "zstd",
    feature = "xz"
))]
#[test]
fn futures_reader_streams_aes_descriptors_one_byte_at_a_time() {
    futures_lite::future::block_on(async {
        let password = b"futures AES pipeline password";
        let payload = b"futures authenticated ZIP payload".repeat(1024);
        let options = password_options([password.to_vec()]);
        for method in [
            ZipMethod::Store,
            ZipMethod::Deflate,
            ZipMethod::Bzip2,
            ZipMethod::Lzma,
            ZipMethod::Ppmd8,
            ZipMethod::Zstd,
            ZipMethod::Xz,
        ] {
            let archive = streaming_aes(method, b"futures.aes", &payload, password);
            let mut reader = AsyncArchiveReader::with_options(
                AsyncOneByte {
                    bytes: archive,
                    position: 0,
                },
                &options,
            )
            .expect("async AES reader");
            let mut decoded = Vec::new();
            loop {
                match reader.next_event().await.unwrap() {
                    ReaderEvent::Data(data) => decoded.extend_from_slice(data),
                    ReaderEvent::Done => break,
                    _ => {},
                }
            }
            assert_eq!(decoded, payload, "{method:?}");
        }
    });
}

#[cfg(all(feature = "tokio", not(target_os = "wasi")))]
#[tokio::test]
async fn tokio_reader_uses_the_same_forward_only_zip_state_machine() {
    let payload = b"tokio ZIP payload".repeat(1024);
    let archive = streaming_zip(ZipMethod::Store, &[(b"tokio.txt", payload.as_slice())]);
    let mut reader = libarchive_oxide::TokioArchiveReader::new(archive.as_slice());
    let mut decoded = Vec::new();
    loop {
        match reader.next_event().await.unwrap() {
            ReaderEvent::Data(data) => decoded.extend_from_slice(data),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(decoded, payload);
}

#[cfg(all(feature = "tokio", feature = "gzip", not(target_os = "wasi")))]
#[tokio::test]
async fn tokio_reader_streams_deflate64_descriptors() {
    let payload = b"tokio Deflate64 descriptor payload".repeat(1024);
    let archive = deflate64_descriptor_zip(b"tokio.d64", &payload, false);
    let mut reader = libarchive_oxide::TokioArchiveReader::new(archive.as_slice());
    let mut decoded = Vec::new();
    loop {
        match reader.next_event().await.unwrap() {
            ReaderEvent::Data(data) => decoded.extend_from_slice(data),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(decoded, payload);
}

#[cfg(all(feature = "tokio", feature = "zstd", not(target_os = "wasi")))]
#[tokio::test]
async fn tokio_reader_streams_zstd_descriptors() {
    let payload = b"tokio Zstandard ZIP payload".repeat(1024);
    let archive = streaming_zip(ZipMethod::Zstd, &[(b"tokio.zst", payload.as_slice())]);
    let mut reader = libarchive_oxide::TokioArchiveReader::new(archive.as_slice());
    let mut decoded = Vec::new();
    loop {
        match reader.next_event().await.unwrap() {
            ReaderEvent::Data(data) => decoded.extend_from_slice(data),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(decoded, payload);
}

#[cfg(all(feature = "tokio", feature = "xz", not(target_os = "wasi")))]
#[tokio::test]
async fn tokio_reader_streams_signed_xz_descriptor() {
    let payload = b"tokio XZ ZIP payload".repeat(1024);
    let archive = streaming_zip(ZipMethod::Xz, &[(b"tokio.xz", &payload)]);
    let mut reader = libarchive_oxide::TokioArchiveReader::new(archive.as_slice());
    let mut decoded = Vec::new();
    loop {
        match reader.next_event().await.unwrap() {
            ReaderEvent::Data(data) => decoded.extend_from_slice(data),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(decoded, payload);
}

#[cfg(all(feature = "tokio", feature = "xz", not(target_os = "wasi")))]
#[tokio::test]
async fn tokio_reader_streams_lzma_descriptor() {
    let payload = b"tokio LZMA descriptor payload".repeat(1024);
    let archive = streaming_zip(ZipMethod::Lzma, &[(b"tokio.lzma", &payload)]);
    let mut reader = libarchive_oxide::TokioArchiveReader::new(archive.as_slice());
    let mut decoded = Vec::new();
    loop {
        match reader.next_event().await.unwrap() {
            ReaderEvent::Data(data) => decoded.extend_from_slice(data),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(decoded, payload);
}

#[cfg(all(feature = "tokio", feature = "ppmd", not(target_os = "wasi")))]
#[tokio::test]
async fn tokio_reader_streams_ppmd_descriptor() {
    let payload = b"tokio PPMd descriptor payload".repeat(1024);
    let archive = streaming_zip(ZipMethod::Ppmd8, &[(b"tokio.ppmd", &payload)]);
    let mut reader = libarchive_oxide::TokioArchiveReader::new(archive.as_slice());
    let mut decoded = Vec::new();
    loop {
        match reader.next_event().await.unwrap() {
            ReaderEvent::Data(data) => decoded.extend_from_slice(data),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(decoded, payload);
}

#[cfg(all(feature = "tokio", feature = "aes", not(target_os = "wasi")))]
#[tokio::test]
async fn tokio_reader_streams_zipcrypto_descriptors() {
    let password = b"tokio encrypted password";
    let payload = b"tokio ZipCrypto ZIP payload".repeat(1024);
    let options = password_options([password.to_vec()]);
    for method in [
        zip::CompressionMethod::Stored,
        zip::CompressionMethod::Deflated,
    ] {
        let archive = independent_zipcrypto("tokio.enc", &payload, password, method);
        let mut reader =
            libarchive_oxide::TokioArchiveReader::with_options(archive.as_slice(), &options)
                .expect("Tokio encrypted reader");
        let mut decoded = Vec::new();
        loop {
            match reader.next_event().await.unwrap() {
                ReaderEvent::Data(data) => decoded.extend_from_slice(data),
                ReaderEvent::Done => break,
                _ => {},
            }
        }
        assert_eq!(decoded, payload, "{method:?}");
    }
}

#[cfg(all(
    feature = "tokio",
    feature = "aes",
    feature = "gzip",
    not(target_os = "wasi")
))]
#[tokio::test]
async fn tokio_reader_streams_zipcrypto_deflate64_descriptor() {
    let password = b"tokio Deflate64 ZipCrypto password";
    let payload = b"tokio ZipCrypto Deflate64 payload".repeat(1024);
    let compressed = stored_deflate64(&payload);
    let archive =
        zipcrypto_deflate64_descriptor(b"tokio.d64", &payload, &compressed, password, false, true);
    let options = password_options([password.to_vec()]);
    let mut reader =
        libarchive_oxide::TokioArchiveReader::with_options(archive.as_slice(), &options)
            .expect("Tokio ZipCrypto Deflate64 reader");
    let mut decoded = Vec::new();
    loop {
        match reader.next_event().await.unwrap() {
            ReaderEvent::Data(data) => decoded.extend_from_slice(data),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(decoded, payload);
}

#[cfg(all(
    feature = "tokio",
    feature = "aes",
    feature = "bzip2",
    feature = "zstd",
    feature = "xz",
    not(target_os = "wasi")
))]
#[tokio::test]
async fn tokio_reader_streams_zipcrypto_pipeline_descriptors() {
    let password = b"tokio encrypted pipeline password";
    let payload = b"tokio ZipCrypto pipeline payload".repeat(1024);
    let options = password_options([password.to_vec()]);
    for method in [
        ZipMethod::Bzip2,
        ZipMethod::Lzma,
        ZipMethod::Ppmd8,
        ZipMethod::Zstd,
        ZipMethod::Xz,
    ] {
        let archive = streaming_zipcrypto(method, b"tokio.pipeline", &payload, password);
        let mut reader =
            libarchive_oxide::TokioArchiveReader::with_options(archive.as_slice(), &options)
                .expect("Tokio encrypted pipeline reader");
        let mut decoded = Vec::new();
        loop {
            match reader.next_event().await.unwrap() {
                ReaderEvent::Data(data) => decoded.extend_from_slice(data),
                ReaderEvent::Done => break,
                _ => {},
            }
        }
        assert_eq!(decoded, payload, "{method:?}");
    }
}

#[cfg(all(
    feature = "tokio",
    feature = "aes",
    feature = "bzip2",
    feature = "zstd",
    feature = "xz",
    not(target_os = "wasi")
))]
#[tokio::test]
async fn tokio_reader_streams_aes_descriptors() {
    let password = b"tokio AES pipeline password";
    let payload = b"tokio authenticated ZIP payload".repeat(1024);
    let options = password_options([password.to_vec()]);
    for method in [
        ZipMethod::Store,
        ZipMethod::Deflate,
        ZipMethod::Bzip2,
        ZipMethod::Lzma,
        ZipMethod::Ppmd8,
        ZipMethod::Zstd,
        ZipMethod::Xz,
    ] {
        let archive = streaming_aes(method, b"tokio.aes", &payload, password);
        let mut reader =
            libarchive_oxide::TokioArchiveReader::with_options(archive.as_slice(), &options)
                .expect("Tokio AES reader");
        let mut decoded = Vec::new();
        loop {
            match reader.next_event().await.unwrap() {
                ReaderEvent::Data(data) => decoded.extend_from_slice(data),
                ReaderEvent::Done => break,
                _ => {},
            }
        }
        assert_eq!(decoded, payload, "{method:?}");
    }
}
