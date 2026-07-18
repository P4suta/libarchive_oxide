#![no_main]
//! Thin libFuzzer shim → the portable `arca_fuzz_cases::codec_zstd` invariant.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    arca_fuzz_cases::codec_zstd(data);
});
