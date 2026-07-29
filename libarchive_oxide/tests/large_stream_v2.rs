// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Automated proof that archive size does not determine reader allocation.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::io::{self, Read};
use std::time::Instant;

use libarchive_oxide::{ArchiveReader, ReaderEvent};
use libarchive_oxide_core::Limits;

const CI_PAYLOAD: u64 = 256 * 1024 * 1024;
const SOAK_PAYLOAD: u64 = 10 * 1024 * 1024 * 1024;
static EXPECTED_DATA: [u8; 64 * 1024] = [0x5a; 64 * 1024];
#[cfg(any(feature = "gzip", feature = "xz", feature = "zstd"))]
const FILTER_FRAME_PAYLOAD: u64 = 8 * 1024 * 1024;
#[cfg(any(feature = "gzip", feature = "xz", feature = "zstd"))]
const MAX_STORED_FILTER_INPUT: usize = 256 * 1024;
#[cfg(target_os = "linux")]
const MAX_PEAK_RSS: u64 = 128 * 1024 * 1024;

fn put_number(field: &mut [u8], mut value: u64) {
    let digits = field.len() - 1;
    if digits >= 22 || value < 1_u64 << (3 * digits) {
        field.fill(b'0');
        for slot in field[..digits].iter_mut().rev() {
            *slot = b'0' + u8::try_from(value & 7).unwrap();
            value >>= 3;
        }
        field[digits] = 0;
        assert_eq!(value, 0);
        return;
    }

    field.fill(0);
    let encoded = value.to_be_bytes();
    let capacity = field.len() - 1;
    assert!(
        capacity >= encoded.len() || encoded[..encoded.len() - capacity].iter().all(|b| *b == 0)
    );
    let copied = capacity.min(encoded.len());
    let destination = field.len() - copied;
    field[destination..].copy_from_slice(&encoded[encoded.len() - copied..]);
    field[0] = 0x80;
}

fn tar_header(payload: u64) -> [u8; 512] {
    let mut header = [0_u8; 512];
    header[..7].copy_from_slice(b"big.bin");
    put_number(&mut header[100..108], 0o644);
    put_number(&mut header[108..116], 0);
    put_number(&mut header[116..124], 0);
    put_number(&mut header[124..136], payload);
    put_number(&mut header[136..148], 0);
    header[148..156].fill(b' ');
    header[156] = b'0';
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    let checksum = header.iter().map(|byte| u64::from(*byte)).sum();
    put_number(&mut header[148..155], checksum);
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

#[cfg(any(feature = "gzip", feature = "xz", feature = "zstd"))]
struct RepeatedByte {
    byte: u8,
    remaining: u64,
}

#[cfg(any(feature = "gzip", feature = "xz", feature = "zstd"))]
impl RepeatedByte {
    fn new(byte: u8, remaining: u64) -> Self {
        Self { byte, remaining }
    }
}

#[cfg(any(feature = "gzip", feature = "xz", feature = "zstd"))]
impl Read for RepeatedByte {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let count = usize::try_from(self.remaining.min(output.len() as u64))
            .map_err(|_| io::Error::other("repeated read length exceeds usize"))?;
        output[..count].fill(self.byte);
        self.remaining -= count as u64;
        Ok(count)
    }
}

/// A constant-memory encoded stream consisting of one header frame, a small
/// payload frame repeated enough times to represent 10 GiB, and one trailer
/// frame. Only the three unique compressed frames are retained.
#[cfg(any(feature = "gzip", feature = "xz", feature = "zstd"))]
struct RepeatedFilteredTar {
    header: Vec<u8>,
    payload: Vec<u8>,
    trailer: Vec<u8>,
    payload_repetitions: u64,
    segment: u64,
    offset: usize,
}

#[cfg(any(feature = "gzip", feature = "xz", feature = "zstd"))]
impl RepeatedFilteredTar {
    fn new(header: Vec<u8>, payload: Vec<u8>, trailer: Vec<u8>) -> Self {
        assert_eq!(SOAK_PAYLOAD % FILTER_FRAME_PAYLOAD, 0);
        assert!(!header.is_empty());
        assert!(!payload.is_empty());
        assert!(!trailer.is_empty());
        assert!(
            header
                .len()
                .checked_add(payload.len())
                .and_then(|size| size.checked_add(trailer.len()))
                .is_some_and(|size| size <= MAX_STORED_FILTER_INPUT),
            "stored compressed frames exceeded the bounded fixture budget"
        );
        Self {
            header,
            payload,
            trailer,
            payload_repetitions: SOAK_PAYLOAD / FILTER_FRAME_PAYLOAD,
            segment: 0,
            offset: 0,
        }
    }

    fn current_segment(&self) -> Option<&[u8]> {
        if self.segment == 0 {
            Some(&self.header)
        } else if self.segment <= self.payload_repetitions {
            Some(&self.payload)
        } else if self.segment == self.payload_repetitions + 1 {
            Some(&self.trailer)
        } else {
            None
        }
    }
}

#[cfg(any(feature = "gzip", feature = "xz", feature = "zstd"))]
impl Read for RepeatedFilteredTar {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let mut written = 0;
        while written < output.len() {
            let (count, segment_len) = {
                let Some(segment) = self.current_segment() else {
                    break;
                };
                let count = (segment.len() - self.offset).min(output.len() - written);
                output[written..written + count]
                    .copy_from_slice(&segment[self.offset..self.offset + count]);
                (count, segment.len())
            };
            written += count;
            self.offset += count;
            if self.offset == segment_len {
                self.segment += 1;
                self.offset = 0;
            }
        }
        Ok(written)
    }
}

fn soak_limits() -> Limits {
    Limits::safe()
        .with_decoded_total(None)
        .with_entry_bytes(None)
}

fn assert_archive<R: Read>(input: R, payload: u64, limits: Limits) -> u64 {
    let mut reader = ArchiveReader::with_limits(input, limits);
    let mut decoded = 0_u64;
    let mut entries = 0_u64;
    loop {
        match reader
            .next_event()
            .unwrap_or_else(|error| panic!("reader failed after {decoded} decoded bytes: {error}"))
        {
            ReaderEvent::Entry(metadata) => {
                entries += 1;
                assert_eq!(metadata.size(), Some(payload));
            },
            ReaderEvent::Data(bytes) => {
                assert!(bytes.len() <= 64 * 1024);
                assert_eq!(bytes, &EXPECTED_DATA[..bytes.len()]);
                decoded += bytes.len() as u64;
            },
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(entries, 1);
    assert_eq!(decoded, payload);
    decoded
}

#[cfg(target_os = "linux")]
fn linux_peak_rss() -> io::Result<u64> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    let line = status
        .lines()
        .find(|line| line.starts_with("VmHWM:"))
        .ok_or_else(|| io::Error::other("VmHWM is absent from /proc/self/status"))?;
    let mut fields = line.split_ascii_whitespace();
    let _label = fields.next();
    let kibibytes = fields
        .next()
        .ok_or_else(|| io::Error::other("VmHWM has no numeric value"))?
        .parse::<u64>()
        .map_err(|error| io::Error::other(format!("invalid VmHWM value: {error}")))?;
    if fields.next() != Some("kB") {
        return Err(io::Error::other("VmHWM is not expressed in kB"));
    }
    kibibytes
        .checked_mul(1024)
        .ok_or_else(|| io::Error::other("VmHWM byte count overflowed"))
}

fn run_soak(label: &str, input: impl Read) {
    let started = Instant::now();
    let decoded = assert_archive(input, SOAK_PAYLOAD, soak_limits());

    #[cfg(target_os = "linux")]
    {
        let peak_rss = linux_peak_rss().expect("Linux peak RSS must be observable");
        eprintln!(
            "{label}: streamed {decoded} bytes in {:?}; peak RSS: {peak_rss} bytes",
            started.elapsed()
        );
        assert!(
            peak_rss <= MAX_PEAK_RSS,
            "{label}: peak RSS {peak_rss} exceeded the {MAX_PEAK_RSS}-byte streaming budget"
        );
    }

    #[cfg(not(target_os = "linux"))]
    eprintln!(
        "{label}: streamed {decoded} bytes in {:?}; the 128 MiB RSS gate is enforced on Linux CI",
        started.elapsed()
    );
}

#[cfg(feature = "gzip")]
fn gzip_frame(mut input: impl Read) -> io::Result<Vec<u8>> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    io::copy(&mut input, &mut encoder)?;
    encoder.finish()
}

#[cfg(feature = "xz")]
fn xz_frame(mut input: impl Read) -> io::Result<Vec<u8>> {
    let mut encoder = xz_codec::write::XzEncoder::new(Vec::new(), 0);
    io::copy(&mut input, &mut encoder)?;
    encoder.finish()
}

#[cfg(feature = "zstd")]
fn zstd_frame(input: impl Read) -> io::Result<Vec<u8>> {
    zstd_codec::stream::encode_all(input, 1)
}

#[test]
fn generated_256_mib_archive_streams_in_bounded_chunks() {
    let _decoded = assert_archive(GeneratedTar::new(CI_PAYLOAD), CI_PAYLOAD, Limits::default());
}

#[test]
#[ignore = "dedicated automated gate: run `just streaming-soak`"]
fn generated_10_gib_archive_streams_without_size_proportional_allocation() {
    run_soak("tar", GeneratedTar::new(SOAK_PAYLOAD));
}

#[test]
#[cfg(feature = "gzip")]
#[ignore = "dedicated automated gate: run `just streaming-soak`"]
fn generated_10_gib_gzip_tar_streams_without_size_proportional_allocation() {
    let header = gzip_frame(io::Cursor::new(tar_header(SOAK_PAYLOAD))).unwrap();
    let payload = gzip_frame(RepeatedByte::new(0x5a, FILTER_FRAME_PAYLOAD)).unwrap();
    let trailer = gzip_frame(RepeatedByte::new(0, 1024)).unwrap();
    run_soak("gzip", RepeatedFilteredTar::new(header, payload, trailer));
}

#[test]
#[cfg(feature = "xz")]
#[ignore = "dedicated automated gate: run `just streaming-soak`"]
fn generated_10_gib_xz_tar_streams_without_size_proportional_allocation() {
    let header = xz_frame(io::Cursor::new(tar_header(SOAK_PAYLOAD))).unwrap();
    let payload = xz_frame(RepeatedByte::new(0x5a, FILTER_FRAME_PAYLOAD)).unwrap();
    let trailer = xz_frame(RepeatedByte::new(0, 1024)).unwrap();
    run_soak("xz", RepeatedFilteredTar::new(header, payload, trailer));
}

#[test]
#[cfg(feature = "zstd")]
#[ignore = "dedicated automated gate: run `just streaming-soak`"]
fn generated_10_gib_zstd_tar_streams_without_size_proportional_allocation() {
    let header = zstd_frame(io::Cursor::new(tar_header(SOAK_PAYLOAD))).unwrap();
    let payload = zstd_frame(RepeatedByte::new(0x5a, FILTER_FRAME_PAYLOAD)).unwrap();
    let trailer = zstd_frame(RepeatedByte::new(0, 1024)).unwrap();
    run_soak("zstd", RepeatedFilteredTar::new(header, payload, trailer));
}
