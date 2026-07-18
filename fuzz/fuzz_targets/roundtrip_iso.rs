#![no_main]
//! Thin libFuzzer shim → the portable `arca_fuzz_cases::roundtrip_iso` invariant.
use arca_fuzz_cases::FuzzEntry;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|entries: Vec<FuzzEntry>| {
    arca_fuzz_cases::roundtrip_iso(&entries);
});
