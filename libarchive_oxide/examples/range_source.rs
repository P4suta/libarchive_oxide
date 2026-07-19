// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Lists a seek-format archive through the `RangeSource` contract.

use std::io;

use libarchive_oxide::{RangeArchiveReader, RangeSource, ReaderEvent, SourceIdentity};

struct MemoryRange {
    bytes: Vec<u8>,
    identity: SourceIdentity,
}

impl RangeSource for MemoryRange {
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }

    fn identity(&self) -> &SourceIdentity {
        &self.identity
    }

    fn read_range(&mut self, offset: u64, output: &mut [u8]) -> io::Result<usize> {
        let start = usize::try_from(offset)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "offset exceeds usize"))?;
        let available = self
            .bytes
            .get(start..)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "offset exceeds source"))?;
        let count = available.len().min(output.len());
        output[..count].copy_from_slice(&available[..count]);
        Ok(count)
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args_os()
        .nth(1)
        .ok_or("usage: range_source ARCHIVE")?;
    let source = MemoryRange {
        bytes: std::fs::read(path)?,
        identity: SourceIdentity::new(b"in-memory-example-v1".to_vec()),
    };
    let mut archive = RangeArchiveReader::new(source)?;
    loop {
        match archive.next_event()? {
            ReaderEvent::Entry(metadata) => {
                println!("{}", metadata.path().display_lossy());
            },
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    let metrics = archive.metrics();
    eprintln!(
        "{} range requests, {} transferred bytes",
        metrics.requests(),
        metrics.transferred_bytes()
    );
    Ok(())
}
