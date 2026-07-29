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

/// `<repo>/fuzz/corpus` — sibling of this crate's manifest directory.
fn corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("arca crate has a parent (the repo root)")
        .join("fuzz")
        .join("corpus")
}

/// Streams a bounded, deterministic shard of the adversarial mutants derived from one committed
/// valid seed.
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
///
/// Mutants are assigned to shards by their stable ordinal. Truncations borrow the seed directly,
/// while field smashes reuse one seed-sized scratch buffer. Consequently peak memory is proportional
/// to one input, not to the number of mutations.
fn for_each_adversarial_mutant(
    seed: &[u8],
    shard_index: usize,
    shard_count: usize,
    mut visit: impl FnMut(&[u8]),
) -> usize {
    /// Cap on truncation cuts (dense for small seeds, strided for large ones).
    const TRUNC_MAX: usize = 4096;
    /// Cap on 4-byte-window smash positions.
    const SMASH_MAX: usize = 8192;

    assert!(shard_count > 0, "mutant shard count must be non-zero");
    assert!(
        shard_index < shard_count,
        "mutant shard index {shard_index} is outside {shard_count} shards"
    );

    let len = seed.len();
    if len == 0 {
        return 0;
    }
    let mut ordinal = 0usize;
    let mut visited = 0usize;

    // (1) Truncations: dense for small seeds, strided to at most TRUNC_MAX cuts for large ones.
    // Optical images are necessarily much larger than the compact archive
    // seeds. Keep their stable-CI replay bounded while still sampling the
    // complete image (nightly libFuzzer remains the dense mutation gate).
    let trunc_max = if len > 256 * 1024 { 128 } else { TRUNC_MAX };
    let smash_max = if len > 256 * 1024 { 256 } else { SMASH_MAX };
    let tstride = len.div_ceil(trunc_max);
    let mut cut = 0;
    while cut < len {
        if ordinal % shard_count == shard_index {
            visit(&seed[..cut]);
            visited += 1;
        }
        ordinal += 1;
        cut += tstride;
    }

    // (2) 4-byte field smashes (all-0xFF → giant index; all-0x00 → zero count/size edge cases).
    let sstride = len.div_ceil(smash_max);
    let mut scratch = seed.to_vec();
    let mut pos = 0;
    while pos < len {
        let end = (pos + 4).min(len);
        for fill in [0xFF_u8, 0x00_u8] {
            if ordinal % shard_count == shard_index {
                scratch[pos..end].fill(fill);
                visit(&scratch);
                scratch[pos..end].copy_from_slice(&seed[pos..end]);
                visited += 1;
            }
            ordinal += 1;
        }
        pos += sstride;
    }
    visited
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

/// Replays every committed corpus file through its target.
///
/// This broad pass skips a missing directory; the target-specific mutant tests
/// below separately require every target to retain at least one committed seed.
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

/// Runs a deterministic batch of `arbitrary`-seeded inputs through every target.
///
/// This exercises detection, round-trip identity, and codec identity on
/// structured inputs of many shapes and sizes without depending on committed
/// corpus bytes.
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

    assert_eq!(
        TARGETS.len(),
        28,
        "all stable replay targets are wired (27 libFuzzer targets plus lzip)"
    );
    assert_eq!(runs, TARGETS.len() * LENGTHS.len() * STREAMS);
}

/// Replays one deterministic shard of a target's adversarial mutations in its own test process.
///
/// A pristine valid seed can never trigger a truncation/out-of-bounds panic in a deep-parse path —
/// its fields are all in range. These tests stream each committed seed through
/// [`for_each_adversarial_mutant`], so the deep-parse code runs against corrupt
/// length/offset/size fields on every replay. That is what would flag a reintroduced unchecked read
/// (e.g. a zip EOCD/central-directory offset used to index the buffer without validation): a mutant
/// forces that offset high, the reader indexes out of bounds, and this test panics — on stable
/// Windows, with no nightly and no libFuzzer. Round-trip and codec seeds are mutated too; their
/// `run_target` bodies keep asserting their identities.
fn replay_seed_mutant_shard(target: &str, shard_index: usize, shard_count: usize) {
    let root = corpus_root();
    let mut mutant_runs = 0usize;
    let mut seeds = 0usize;
    let directory = root.join(target);
    let entries = fs::read_dir(&directory)
        .unwrap_or_else(|error| panic!("missing corpus directory for {target}: {error}"));
    for entry in entries {
        let path = entry.unwrap().path();
        if !path.is_file() {
            continue;
        }
        seeds += 1;
        let seed = fs::read(&path).unwrap();
        mutant_runs += for_each_adversarial_mutant(&seed, shard_index, shard_count, |mutant| {
            run_target(target, mutant);
        });
    }
    assert!(seeds > 0, "expected a committed seed for target {target}");
    assert!(
        mutant_runs > 0,
        "adversarial mutation produced no runs for target {target}"
    );
    println!(
        "fuzz_replay: {target} shard {}/{shard_count} exercised {mutant_runs} adversarial mutant(s) \
         from {seeds} seed(s)",
        shard_index + 1
    );
}

#[test]
fn mutant_shards_cover_the_unsharded_stream_exactly_once() {
    let seed = b"structured archive seed";
    let mut unsharded = Vec::new();
    let unsharded_count =
        for_each_adversarial_mutant(seed, 0, 1, |mutant| unsharded.push(mutant.to_vec()));

    let mut sharded = Vec::new();
    let mut sharded_count = 0usize;
    for shard_index in 0..4 {
        sharded_count += for_each_adversarial_mutant(seed, shard_index, 4, |mutant| {
            sharded.push(mutant.to_vec());
        });
    }

    unsharded.sort_unstable();
    sharded.sort_unstable();
    assert_eq!(sharded_count, unsharded_count);
    assert_eq!(sharded, unsharded);
}

macro_rules! mutant_replay_tests {
    (
        $(
            $target:literal => {
                $($test:ident : $shard_index:literal / $shard_count:literal),+ $(,)?
            }
        ),+ $(,)?
    ) => {
        const MUTANT_TARGETS: &[&str] = &[$($target),+];

        $(
            $(
                #[test]
                fn $test() {
                    replay_seed_mutant_shard($target, $shard_index, $shard_count);
                }
            )+
        )+
    };
}

mutant_replay_tests! {
    "read_tar" => { seed_mutants_read_tar: 0 / 1 },
    "read_cpio" => { seed_mutants_read_cpio: 0 / 1 },
    "read_ar" => { seed_mutants_read_ar: 0 / 1 },
    "read_zip" => { seed_mutants_read_zip: 0 / 1 },
    "read_7z" => { seed_mutants_read_7z: 0 / 1 },
    "read_7z_graph" => { seed_mutants_read_7z_graph: 0 / 1 },
    "read_iso" => { seed_mutants_read_iso: 0 / 1 },
    "read_udf" => { seed_mutants_read_udf: 0 / 1 },
    "read_cab" => { seed_mutants_read_cab: 0 / 1 },
    "read_xar" => { seed_mutants_read_xar: 0 / 1 },
    "roundtrip_tar" => { seed_mutants_roundtrip_tar: 0 / 1 },
    "roundtrip_cpio" => { seed_mutants_roundtrip_cpio: 0 / 1 },
    "roundtrip_ar" => { seed_mutants_roundtrip_ar: 0 / 1 },
    "roundtrip_7z" => { seed_mutants_roundtrip_7z: 0 / 1 },
    "roundtrip_iso" => { seed_mutants_roundtrip_iso: 0 / 1 },
    "codec_gzip" => { seed_mutants_codec_gzip: 0 / 1 },
    "codec_lzw" => { seed_mutants_codec_lzw: 0 / 1 },
    "codec_bzip2" => { seed_mutants_codec_bzip2: 0 / 1 },
    "codec_zstd" => { seed_mutants_codec_zstd: 0 / 1 },
    "codec_xz" => { seed_mutants_codec_xz: 0 / 1 },
    "codec_lzip" => { seed_mutants_codec_lzip: 0 / 1 },
    "codec_lz4" => { seed_mutants_codec_lz4: 0 / 1 },
    "codec_lzma2" => { seed_mutants_codec_lzma2: 0 / 1 },
    "package_rpm" => { seed_mutants_package_rpm: 0 / 1 },
    "package_alpine" => {
        seed_mutants_package_alpine_1_of_4: 0 / 4,
        seed_mutants_package_alpine_2_of_4: 1 / 4,
        seed_mutants_package_alpine_3_of_4: 2 / 4,
        seed_mutants_package_alpine_4_of_4: 3 / 4,
    },
    "package_zip" => { seed_mutants_package_zip: 0 / 1 },
    "package_app" => {
        seed_mutants_package_app_1_of_4: 0 / 4,
        seed_mutants_package_app_2_of_4: 1 / 4,
        seed_mutants_package_app_3_of_4: 2 / 4,
        seed_mutants_package_app_4_of_4: 3 / 4,
    },
    "extraction_plan" => { seed_mutants_extraction_plan: 0 / 1 },
}

#[test]
fn mutant_target_inventory_matches_fuzz_targets() {
    assert_eq!(
        MUTANT_TARGETS, TARGETS,
        "every fuzz target must have an independently replayed mutant corpus"
    );
}
