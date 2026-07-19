// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! CI-scale proof that archive size does not determine reader allocation.

#![allow(clippy::panic, clippy::unwrap_used)]

use std::io::{self, Read};

use libarchive_oxide::{ArchiveReader, ReaderEvent};
use libarchive_oxide_core::Limits;

const CI_PAYLOAD: u64 = 256 * 1024 * 1024;
const MANUAL_PAYLOAD: u64 = 10 * 1024 * 1024 * 1024;

fn put_octal(field: &mut [u8], mut value: u64) {
    field.fill(b'0');
    let last = field.len() - 1;
    for slot in field[..last].iter_mut().rev() {
        *slot = b'0' + u8::try_from(value & 7).unwrap();
        value >>= 3;
    }
    field[last] = 0;
    assert_eq!(value, 0);
}

fn tar_header(payload: u64) -> [u8; 512] {
    let mut header = [0_u8; 512];
    header[..7].copy_from_slice(b"big.bin");
    put_octal(&mut header[100..108], 0o644);
    put_octal(&mut header[108..116], 0);
    put_octal(&mut header[116..124], 0);
    put_octal(&mut header[124..136], payload);
    put_octal(&mut header[136..148], 0);
    header[148..156].fill(b' ');
    header[156] = b'0';
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    let checksum = header.iter().map(|byte| u64::from(*byte)).sum();
    put_octal(&mut header[148..155], checksum);
    header[155] = b' ';
    header
}

struct GeneratedTar {
    header: [u8; 512],
    payload: u64,
    total: u64,
    position: u64,
}

impl GeneratedTar {
    fn new(payload: u64) -> Self {
        let padding = (512 - payload % 512) % 512;
        Self {
            header: tar_header(payload),
            payload,
            total: 512 + payload + padding + 1024,
            position: 0,
        }
    }
}

impl Read for GeneratedTar {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() || self.position == self.total {
            return Ok(0);
        }
        let count = usize::try_from((self.total - self.position).min(output.len() as u64))
            .map_err(|_| io::Error::other("generated read length exceeds usize"))?;
        let mut written = 0;
        while written < count {
            if self.position < 512 {
                let start = usize::try_from(self.position)
                    .map_err(|_| io::Error::other("header offset exceeds usize"))?;
                let amount = (512 - start).min(count - written);
                output[written..written + amount]
                    .copy_from_slice(&self.header[start..start + amount]);
                self.position += amount as u64;
                written += amount;
            } else if self.position < 512 + self.payload {
                let amount = usize::try_from(512 + self.payload - self.position)
                    .unwrap_or(usize::MAX)
                    .min(count - written);
                output[written..written + amount].fill(0x5a);
                self.position += amount as u64;
                written += amount;
            } else {
                output[written..count].fill(0);
                self.position += (count - written) as u64;
                written = count;
            }
        }
        Ok(count)
    }
}

fn assert_generated_archive(payload: u64, limits: Limits) {
    let mut reader = ArchiveReader::with_limits(GeneratedTar::new(payload), limits);
    let mut decoded = 0_u64;
    loop {
        match reader
            .next_event()
            .unwrap_or_else(|error| panic!("reader failed after {decoded} decoded bytes: {error}"))
        {
            ReaderEvent::Entry(metadata) => assert_eq!(metadata.size(), Some(payload)),
            ReaderEvent::Data(bytes) => {
                assert!(bytes.len() <= 64 * 1024);
                assert!(bytes.iter().all(|byte| *byte == 0x5a));
                decoded += bytes.len() as u64;
            },
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(decoded, payload);
}

#[test]
fn generated_256_mib_archive_streams_in_bounded_chunks() {
    assert_generated_archive(CI_PAYLOAD, Limits::default());
}

#[test]
#[ignore = "manual 10 GiB bounded-memory soak"]
fn generated_10_gib_archive_streams_without_size_proportional_allocation() {
    assert_generated_archive(MANUAL_PAYLOAD, Limits::unlimited());
}
