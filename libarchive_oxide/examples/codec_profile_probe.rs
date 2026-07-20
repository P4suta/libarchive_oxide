// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Reproducible streaming throughput and resident-memory probe for codec profiles.

use std::env;
use std::io::{self, Cursor};
#[cfg(any(target_os = "windows", target_os = "macos"))]
use std::process::Command;
use std::time::Instant;

use libarchive_oxide::{ArchiveReader, ArchiveWriter, ReaderEvent};
use libarchive_oxide_core::filter::FilterId;
use libarchive_oxide_core::{ArchivePath, EntryKind, EntryMetadata, FormatId, Limits};

const CHUNK: usize = 64 * 1024;
const SAMPLE_INTERVAL: u64 = 8 * 1024 * 1024;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args().skip(1);
    let filter_name = arguments
        .next()
        .ok_or("usage: codec_profile_probe FILTER [MIB]")?;
    let mebibytes = arguments
        .next()
        .map_or(Ok(64_u64), |value| value.parse::<u64>())?;
    if arguments.next().is_some() || mebibytes == 0 {
        return Err("usage: codec_profile_probe FILTER [MIB]".into());
    }
    let filter = parse_filter(&filter_name)?;
    let payload_bytes = mebibytes
        .checked_mul(1024 * 1024)
        .ok_or("payload size overflow")?;
    let baseline_rss = resident_bytes().unwrap_or(0);
    let mut peak_rss = baseline_rss;

    let metadata = EntryMetadata::builder(
        EntryKind::File,
        ArchivePath::from_bytes(b"profile-probe.bin".to_vec()),
    )
    .size(Some(payload_bytes))
    .build();
    let started = Instant::now();
    let mut writer =
        ArchiveWriter::with_filter(Vec::new(), FormatId::Tar, Some(filter), Limits::default())?;
    writer.start_entry(&metadata)?;
    let chunk = vec![0x5a_u8; CHUNK];
    let mut written = 0_u64;
    let mut next_sample = SAMPLE_INTERVAL;
    while written < payload_bytes {
        let count = usize::try_from((payload_bytes - written).min(CHUNK as u64))?;
        writer.write_data(&chunk[..count])?;
        written += count as u64;
        if written >= next_sample {
            peak_rss = peak_rss.max(resident_bytes().unwrap_or(peak_rss));
            next_sample = next_sample.saturating_add(SAMPLE_INTERVAL);
        }
    }
    writer.end_entry()?;
    let archive = writer.finish()?;
    let encode_millis = started.elapsed().as_millis();
    peak_rss = peak_rss.max(resident_bytes().unwrap_or(peak_rss));

    let started = Instant::now();
    let mut reader = ArchiveReader::with_limits(Cursor::new(archive.as_slice()), Limits::default());
    let mut decoded = 0_u64;
    next_sample = SAMPLE_INTERVAL;
    loop {
        match reader.next_event()? {
            ReaderEvent::Data(bytes) => {
                decoded = decoded
                    .checked_add(bytes.len() as u64)
                    .ok_or("decode count overflow")?;
                if decoded >= next_sample {
                    peak_rss = peak_rss.max(resident_bytes().unwrap_or(peak_rss));
                    next_sample = next_sample.saturating_add(SAMPLE_INTERVAL);
                }
            },
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    let decode_millis = started.elapsed().as_millis();
    peak_rss = peak_rss.max(resident_bytes().unwrap_or(peak_rss));
    if decoded != payload_bytes {
        return Err(format!("decoded {decoded} bytes, expected {payload_bytes}").into());
    }

    let profile = if cfg!(feature = "native-codecs") {
        "native"
    } else {
        "portable"
    };
    println!(
        "{{\"profile\":\"{profile}\",\"filter\":\"{filter_name}\",\
         \"payload_bytes\":{payload_bytes},\"archive_bytes\":{},\
         \"encode_millis\":{encode_millis},\"decode_millis\":{decode_millis},\
         \"baseline_rss_bytes\":{baseline_rss},\"peak_rss_bytes\":{peak_rss},\
         \"additional_rss_bytes\":{}}}",
        archive.len(),
        peak_rss.saturating_sub(baseline_rss)
    );
    Ok(())
}

fn parse_filter(name: &str) -> Result<FilterId, Box<dyn std::error::Error>> {
    match name {
        "gzip" => Ok(FilterId::Gzip),
        "bzip2" => Ok(FilterId::Bzip2),
        "zstd" => Ok(FilterId::Zstd),
        "xz" => Ok(FilterId::Xz),
        "lz4" => Ok(FilterId::Lz4),
        _ => Err(format!("unsupported filter {name:?}").into()),
    }
}

#[cfg(target_os = "linux")]
fn resident_bytes() -> io::Result<u64> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    let kibibytes = status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))
        .and_then(|value| value.split_whitespace().next())
        .ok_or_else(|| io::Error::other("VmRSS is missing from /proc/self/status"))?
        .parse::<u64>()
        .map_err(io::Error::other)?;
    kibibytes
        .checked_mul(1024)
        .ok_or_else(|| io::Error::other("resident byte count overflow"))
}

#[cfg(target_os = "windows")]
fn resident_bytes() -> io::Result<u64> {
    let output = Command::new("powershell.exe")
        .args([
            "-NoLogo",
            "-NoProfile",
            "-Command",
            &format!("(Get-Process -Id {}).WorkingSet64", std::process::id()),
        ])
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other("Get-Process failed"));
    }
    String::from_utf8(output.stdout)
        .map_err(io::Error::other)?
        .trim()
        .parse::<u64>()
        .map_err(io::Error::other)
}

#[cfg(target_os = "macos")]
fn resident_bytes() -> io::Result<u64> {
    let output = Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other("ps failed"));
    }
    let kibibytes = String::from_utf8(output.stdout)
        .map_err(io::Error::other)?
        .trim()
        .parse::<u64>()
        .map_err(io::Error::other)?;
    kibibytes
        .checked_mul(1024)
        .ok_or_else(|| io::Error::other("resident byte count overflow"))
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
fn resident_bytes() -> io::Result<u64> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "resident memory sampling is unsupported on this platform",
    ))
}
