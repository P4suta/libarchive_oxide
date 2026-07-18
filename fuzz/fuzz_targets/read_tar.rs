#![no_main]
//! Thin libFuzzer shim → the portable `libarchive_oxide_fuzz_cases::read_tar` invariant.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    libarchive_oxide_fuzz_cases::read_tar(data);
});
