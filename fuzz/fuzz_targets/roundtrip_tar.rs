#![no_main]
//! Thin libFuzzer shim → the portable `libarchive_oxide_fuzz_cases::roundtrip_tar` invariant.
use libarchive_oxide_fuzz_cases::FuzzEntry;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|entries: Vec<FuzzEntry>| {
    libarchive_oxide_fuzz_cases::roundtrip_tar(&entries);
});
