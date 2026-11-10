// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_main]

//! Thin libFuzzer shim for bounded RAR 3.x/4.x container, volume, and Store decoding.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    libarchive_oxide_fuzz_cases::read_rar_legacy(data);
});
