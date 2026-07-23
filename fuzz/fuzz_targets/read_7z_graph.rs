// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_main]

//! Thin libFuzzer shim → the portable `libarchive_oxide_fuzz_cases::read_7z_graph` invariant, which
//! synthesizes a random 7z `StreamsInfo` coder graph and asserts the reader never panics, stays
//! bounded, and only ever returns a typed error.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    libarchive_oxide_fuzz_cases::read_7z_graph(data);
});
