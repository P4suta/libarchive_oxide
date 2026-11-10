// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_main]

//! Thin libFuzzer shim for the strict Base64 protocol and round-trip invariant.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    libarchive_oxide_fuzz_cases::codec_base64(data);
});
