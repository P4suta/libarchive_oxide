// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Driving the `no_std + alloc` core without giving it an I/O object.

use libarchive_oxide_core::{ArchiveDecoder, DecodeEvent, EndOfInput, Limits, TarDecoder};

fn main() -> Result<(), libarchive_oxide_core::ArchiveError> {
    let archive = [0_u8; 1024];
    let mut decoder = TarDecoder::new(Limits::default());
    let mut position = 0;
    let mut scratch = [0_u8; 4096];

    loop {
        let step = decoder.step(&archive[position..], &mut scratch, EndOfInput::End)?;
        position += step.consumed;
        if matches!(step.event, DecodeEvent::Done) {
            return Ok(());
        }
    }
}
