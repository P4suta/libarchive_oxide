// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_main]

//! Thin libFuzzer shim for bounded XAR Store/zlib/BZip2 writer/reader invariants.
use libarchive_oxide_fuzz_cases::FuzzEntry;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|entries: Vec<FuzzEntry>| {
    libarchive_oxide_fuzz_cases::roundtrip_xar(&entries);
});
