// SPDX-FileCopyrightText: 2026 Karpeles Lab Inc.
// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT

//! RAR5 post-decompression filters.

use alloc::vec::Vec;

use crate::codec::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FilterKind {
    Delta { channels: u8 },
    X86Call,
    X86CallJmp,
    Arm,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct Filter {
    pub(super) start: u64,
    pub(super) length: u32,
    pub(super) kind: FilterKind,
}

pub(super) fn apply(filter: Filter, buf: &mut [u8]) -> Result<(), Error> {
    let length = usize::try_from(filter.length).map_err(|_| Error::Corrupt)?;
    if buf.len() < length {
        return Err(Error::Corrupt);
    }
    match filter.kind {
        FilterKind::X86Call => apply_e8(filter.start, &mut buf[..length], false),
        FilterKind::X86CallJmp => apply_e8(filter.start, &mut buf[..length], true),
        FilterKind::Delta { channels } => apply_delta(&mut buf[..length], channels),
        FilterKind::Arm => apply_arm(filter.start, &mut buf[..length]),
    }
}

fn apply_delta(buf: &mut [u8], channels: u8) -> Result<(), Error> {
    let channels = usize::from(channels);
    if channels == 0 {
        return Err(Error::Corrupt);
    }

    // The encoded bytes are grouped by channel, while decoded bytes are interleaved.
    // Preserve the encoded order because source and destination ranges overlap for every multi-channel filter.
    let encoded = Vec::from(&*buf);
    let mut source = 0usize;
    for channel in 0..channels {
        let mut previous = 0u8;
        for destination in (channel..buf.len()).step_by(channels) {
            let difference = *encoded.get(source).ok_or(Error::Corrupt)?;
            previous = previous.wrapping_sub(difference);
            buf[destination] = previous;
            source += 1;
        }
    }
    if source != encoded.len() {
        return Err(Error::Corrupt);
    }
    Ok(())
}

fn apply_arm(start: u64, buf: &mut [u8]) -> Result<(), Error> {
    for index in (0..buf.len().saturating_sub(3)).step_by(4) {
        if buf[index + 3] != 0xeb {
            continue;
        }
        let word = u32::from_le_bytes([buf[index], buf[index + 1], buf[index + 2], buf[index + 3]]);
        let instruction = start.wrapping_add(index as u64) / 4;
        let instruction = u32::try_from(instruction & 0x00ff_ffff).map_err(|_| Error::Corrupt)?;
        let decoded = word.wrapping_sub(instruction).wrapping_rem(1 << 24) | 0xeb00_0000;
        buf[index..index + 4].copy_from_slice(&decoded.to_le_bytes());
    }
    Ok(())
}

fn apply_e8(start: u64, buf: &mut [u8], extended: bool) -> Result<(), Error> {
    const FILE_SIZE: u32 = 0x0100_0000;
    if buf.len() < 5 {
        return Ok(());
    }
    let last = buf.len() - 4;
    let mut index = 0;
    while index < last {
        let opcode = buf[index];
        if opcode != 0xe8 && !(extended && opcode == 0xe9) {
            index += 1;
            continue;
        }
        let relative = u32::from_le_bytes([
            buf[index + 1],
            buf[index + 2],
            buf[index + 3],
            buf[index + 4],
        ]);
        let absolute = start.wrapping_add(index as u64).wrapping_add(1);
        let offset =
            u32::try_from(absolute & u64::from(FILE_SIZE - 1)).map_err(|_| Error::Corrupt)?;
        let decoded = if (relative & 0x8000_0000) != 0
            && (relative.wrapping_add(offset) & 0x8000_0000) == 0
        {
            relative.wrapping_add(FILE_SIZE)
        } else if (relative.wrapping_sub(FILE_SIZE) & 0x8000_0000) != 0 {
            relative.wrapping_sub(offset)
        } else {
            relative
        };
        buf[index + 1..index + 5].copy_from_slice(&decoded.to_le_bytes());
        index += 5;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::{Filter, FilterKind, apply};
    use crate::codec::Error;

    fn filter(kind: FilterKind, start: u64, length: usize) -> Filter {
        Filter {
            start,
            length: u32::try_from(length).unwrap_or(u32::MAX),
            kind,
        }
    }

    #[test]
    fn delta_decodes_planar_channel_differences() {
        let mut bytes = vec![0xff, 0xff, 246, 246, 156, 10];
        let descriptor = filter(FilterKind::Delta { channels: 3 }, 0, bytes.len());

        apply(descriptor, &mut bytes).expect("valid three-channel delta filter");

        assert_eq!(bytes, [1, 10, 100, 2, 20, 90]);
    }

    #[test]
    fn delta_rejects_zero_channels() {
        let mut bytes = vec![0; 8];
        let descriptor = filter(FilterKind::Delta { channels: 0 }, 0, bytes.len());

        assert_eq!(apply(descriptor, &mut bytes), Err(Error::Corrupt));
    }

    #[test]
    fn arm_decodes_branch_offsets_and_leaves_other_words_unchanged() {
        let mut bytes = vec![0x20, 0, 0, 0xeb, 0x78, 0x56, 0x34, 0x12];
        let descriptor = filter(FilterKind::Arm, 16, bytes.len());

        apply(descriptor, &mut bytes).expect("valid ARM filter");

        assert_eq!(bytes, [0x1c, 0, 0, 0xeb, 0x78, 0x56, 0x34, 0x12]);
    }

    #[test]
    fn filter_rejects_a_region_shorter_than_its_descriptor() {
        let mut bytes = vec![0; 3];
        let descriptor = filter(FilterKind::Arm, 0, 4);

        assert_eq!(apply(descriptor, &mut bytes), Err(Error::Corrupt));
    }

    #[test]
    fn x86_call_filter_preserves_existing_behavior() {
        let mut bytes = vec![0, 0, 0xe8, 0x10, 0, 0, 0, 0x90, 0x90];
        let descriptor = filter(FilterKind::X86Call, 0, bytes.len());

        apply(descriptor, &mut bytes).expect("valid x86 filter");

        assert_eq!(&bytes[3..7], &0x0du32.to_le_bytes());
    }

    #[test]
    fn x86_call_jump_filter_handles_e9() {
        let mut bytes = vec![0xe9, 0x10, 0, 0, 0];
        let descriptor = filter(FilterKind::X86CallJmp, 0, bytes.len());

        apply(descriptor, &mut bytes).expect("valid extended x86 filter");

        assert_eq!(&bytes[1..5], &0x0fu32.to_le_bytes());
    }
}
