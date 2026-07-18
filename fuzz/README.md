# arca fuzzing

This directory is a **cargo-fuzz** workspace, deliberately **excluded** from the main workspace
(`exclude = ["fuzz"]` in the root `Cargo.toml`) so `cargo test --workspace` never tries to build
the libFuzzer targets — they need a nightly toolchain and a sanitizer runtime that is not available
on the Windows/MSVC dev box.

## Layout

- `fuzz_lib/` (`arca-fuzz-cases`) — the invariant bodies as **plain functions**, no libFuzzer. Builds
  on stable, everywhere. This is the single source of truth for what each target checks.
- `fuzz_targets/*.rs` — one thin `fuzz_target!` shim per target, each delegating to a `fuzz_lib`
  function. Compiled only under this crate (nightly `cargo fuzz`).
- `corpus/<target>/` — committed seed inputs (tiny valid archives / compressed streams per format).

## Targets

- **Readers** (`read_tar`, `read_cpio`, `read_ar`, `read_zip`, `read_7z`, `read_iso`): arbitrary
  bytes → detection + `next_entry` + `read_chunk` to EOF, asserting no panic and bounded work.
- **Round-trips** (`roundtrip_tar`, `roundtrip_cpio`, `roundtrip_ar`, `roundtrip_7z`, `roundtrip_iso`):
  an `arbitrary`-synthesized file set → write → read back → assert `read ∘ write = id`.
- **Codecs** (`codec_gzip`, `codec_zstd`, `codec_xz`, `codec_lz4`, `codec_lzma2`): decode arbitrary
  bytes without panicking, and assert `decode ∘ encode = id` where an encoder exists.

## Running

Nightly + `cargo-fuzz` (Linux CI). CI (`.github/workflows/ci.yml`, `fuzz` job) both **builds** every
target and **runs** each one for a short bounded budget seeded from its corpus, so the fuzzer acts as
a real bug-finder — not just a compile check:

```sh
cargo install cargo-fuzz
cd fuzz
cargo +nightly fuzz build                          # smoke-build every target
cargo +nightly fuzz run read_tar                   # fuzz one target
cargo +nightly fuzz run read_zip -- -max_total_time=30   # bounded run, as CI does
```

Portable gate (no nightly, no libFuzzer — the Windows dev box):

```sh
cargo test -p arca --test fuzz_replay
```

`arca/tests/fuzz_replay.rs` replays, through the same `arca-fuzz-cases` functions the fuzzer uses:

1. every committed corpus file,
2. a batch of deterministic `arbitrary`-seeded inputs, and
3. **adversarial mutants of each seed** (truncations + `u32`-field smashes). This is what gives the
   `read_*` targets genuine deep-parse coverage on the portable gate: a pristine valid seed can't
   trip a truncation/out-of-bounds panic, but a corrupted-yet-still-detected one can, so a
   reintroduced unchecked length/offset read fails `cargo test` here without needing nightly.
