// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Portable fuzz replay — the Windows/MSVC dev-box gate that needs neither nightly nor libFuzzer.
//!
//! It drives the **same** invariant functions the cargo-fuzz targets use (`libarchive_oxide_fuzz_cases`) over
//! three input sources:
//!
//! 1. every committed corpus file under `fuzz/corpus/<target>/`,
//! 2. a batch of `arbitrary`-seeded structured inputs generated from **deterministic** seeds (a
//!    splitmix64 stream — no `rand`, no clock), so the run is byte-for-byte reproducible, and
//! 3. **adversarial mutants of each committed seed** (truncations + `u32`-field smashes). This is
//!    the one that actually stresses the *reader* deep-parse paths: a reader gates deep parsing
//!    behind a signature/magic/checksum, so a random seed is rejected at the door and never reaches
//!    the length/offset arithmetic where a missing bounds check panics — but a corruption of a
//!    seed that *already passes detection* does. Without it the read_* targets only ever deep-parse
//!    their one pristine valid seed, which by construction cannot trigger an out-of-bounds panic.
//!
//! A failure here means an invariant broke (a panic, a broken round-trip, or a broken codec
//! identity) — exactly what the fuzzer would flag, but reachable on stable Windows.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};

use libarchive_oxide_fuzz_cases::{TARGETS, run_target};

/// `<repo>/fuzz/corpus` — sibling of this crate's manifest directory (`<repo>/arca`).
fn corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("arca crate has a parent (the repo root)")
        .join("fuzz")
        .join("corpus")
}

/// Bounded, deterministic adversarial mutants of one committed valid seed.
///
/// The cargo-fuzz targets get hostile inputs from libFuzzer's coverage-guided mutator. The portable
/// gate has no mutator, and a *random* seed is worthless against a reader that gates deep parsing
/// behind a signature/magic/checksum (7z, zip, cpio, ar, tar, iso all do): random bytes are rejected
/// at the door and never reach the length/offset/size arithmetic where a missing bounds check
/// panics. So we derive, from a seed that *already passes detection*, a family of corruptions that
/// keep enough structure to get past detection while smashing the interior fields — the inputs that
/// actually exercise truncation and out-of-bounds handling.
///
/// Two strategies, each bounded regardless of seed size (the iso seed is ~58 KiB):
/// * **Truncations** — a header that promises more bytes than remain is the classic panic trigger;
///   every prefix (strided on large seeds) is tried.
/// * **`u32`-field smashes** — force a sliding 4-byte little-endian window to all-`0xFF` (max value,
///   most likely to overflow an index) and to all-`0x00`, at a stride fine enough that every
///   4-byte length/offset/size field gets at least one byte forced out of range. For back-loaded
///   formats (zip's EOCD + central directory live at the tail) this reaches the offset fields while
///   leaving the signature elsewhere intact — exactly the shape that trips an unchecked slice index.
fn adversarial_mutants(seed: &[u8]) -> Vec<Vec<u8>> {
    /// Cap on truncation cuts (dense for small seeds, strided for large ones).
    const TRUNC_MAX: usize = 4096;
    /// Cap on 4-byte-window smash positions.
    const SMASH_MAX: usize = 8192;

    let len = seed.len();
    let mut out = Vec::new();
    if len == 0 {
        return out;
    }

    // (1) Truncations: dense for small seeds, strided to at most TRUNC_MAX cuts for large ones.
    let tstride = len.div_ceil(TRUNC_MAX);
    let mut cut = 0;
    while cut < len {
        out.push(seed[..cut].to_vec());
        cut += tstride;
    }

    // (2) 4-byte field smashes (all-0xFF → giant index; all-0x00 → zero count/size edge cases).
    let sstride = len.div_ceil(SMASH_MAX);
    let mut pos = 0;
    while pos < len {
        let end = (pos + 4).min(len);
        for fill in [0xFF_u8, 0x00_u8] {
            let mut m = seed.to_vec();
            m[pos..end].fill(fill);
            out.push(m);
        }
        pos += sstride;
    }
    out
}

/// A deterministic splitmix64 byte stream — reproducible structured-input seeds, no external rng.
fn seed_bytes(mut state: u64, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        out.extend_from_slice(&z.to_le_bytes());
    }
    out.truncate(len);
    out
}

/// Replays every committed corpus file through its target. Missing corpus is not a failure (the
/// arbitrary batch still runs); this just guarantees the seeds we ship stay panic-free.
#[test]
fn corpus_files_replay_without_panic() {
    let root = corpus_root();
    let mut processed = 0usize;
    for &target in TARGETS {
        let dir = root.join(target);
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries {
            let path = entry.unwrap().path();
            if !path.is_file() {
                continue;
            }
            let data = fs::read(&path).unwrap();
            run_target(target, &data);
            processed += 1;
        }
    }
    // Informative only: a fresh checkout ships seeds, but an empty corpus is still a valid state.
    println!("fuzz_replay: replayed {processed} committed corpus file(s)");
}

/// Runs a deterministic batch of `arbitrary`-seeded inputs through every target. This is the real
/// portable gate: it exercises detection, round-trip identity, and codec identity on structured
/// inputs of many shapes and sizes without depending on any committed corpus.
#[test]
fn arbitrary_seeds_uphold_invariants() {
    // A spread of lengths so `arbitrary` synthesizes everything from empty to multi-entry sets.
    const LENGTHS: &[usize] = &[0, 1, 2, 3, 7, 15, 31, 63, 127, 255, 511, 1023, 4095];
    const STREAMS: usize = 3;

    let mut runs = 0usize;
    for (t, &target) in TARGETS.iter().enumerate() {
        for &len in LENGTHS {
            for stream in 0..STREAMS {
                // A distinct, reproducible seed per (target, length, stream).
                let state = (t as u64)
                    .wrapping_mul(0x1000_0001)
                    .wrapping_add(len as u64)
                    .wrapping_mul(0x100_0001)
                    .wrapping_add((stream as u64).wrapping_mul(0xDEAD_BEEF));
                let data = seed_bytes(state | 1, len);
                run_target(target, &data);
                runs += 1;
            }
        }
    }

    assert_eq!(TARGETS.len(), 18, "all fuzz targets are wired");
    assert_eq!(runs, TARGETS.len() * LENGTHS.len() * STREAMS);
}

/// The real adversarial portable gate for the **reader** paths.
///
/// A pristine valid seed can never trigger a truncation/out-of-bounds panic in a deep-parse path —
/// its fields are all in range. This test feeds each committed seed through [`adversarial_mutants`],
/// so the deep-parse code runs against corrupt length/offset/size fields on every replay. That is
/// what would flag a reintroduced unchecked read (e.g. a zip EOCD/central-directory offset used to
/// index the buffer without validation): a mutant forces that offset high, the reader indexes out of
/// bounds, and this test panics — on stable Windows, with no nightly and no libFuzzer. Round-trip
/// and codec seeds are mutated too; their `run_target` bodies keep asserting their identities.
#[test]
fn seed_mutants_uphold_invariants() {
    let root = corpus_root();
    let mut mutant_runs = 0usize;
    let mut targets_with_seed = 0usize;
    for &target in TARGETS {
        let dir = root.join(target);
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        let mut had_seed = false;
        for entry in entries {
            let path = entry.unwrap().path();
            if !path.is_file() {
                continue;
            }
            had_seed = true;
            let seed = fs::read(&path).unwrap();
            for mutant in adversarial_mutants(&seed) {
                run_target(target, &mutant);
                mutant_runs += 1;
            }
        }
        if had_seed {
            targets_with_seed += 1;
        }
    }

    // Require seeds for all six reader targets.
    assert!(
        targets_with_seed >= 6,
        "expected committed seeds for at least the six read_* targets, saw {targets_with_seed}"
    );
    assert!(mutant_runs > 0, "adversarial mutation produced no runs");
    println!(
        "fuzz_replay: exercised {mutant_runs} adversarial seed mutant(s) across {targets_with_seed} \
         seeded target(s)"
    );
}
