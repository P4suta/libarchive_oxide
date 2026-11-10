// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_main]

//! Thin libFuzzer shim for bounded lzop framing and round-trip invariants.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    libarchive_oxide_fuzz_cases::codec_lzop(data);
});
