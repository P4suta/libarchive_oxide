# Fuzzing

This excluded Cargo workspace contains libFuzzer targets. It requires nightly
Rust and a sanitizer runtime.

## Layout

| Path | Purpose |
|---|---|
| `fuzz_lib` | portable invariant functions |
| `fuzz_targets` | `cargo-fuzz` entry points |
| `corpus` | committed seeds |

Targets cover archive readers, archive round trips, and codecs.

## Commands

```sh
cd fuzz
cargo +nightly fuzz build
cargo +nightly fuzz run read_tar
cargo +nightly fuzz run read_zip -- -max_total_time=30
```

Portable replay:

```sh
cargo test -p libarchive_oxide --test fuzz_replay
```

CI builds every target, performs bounded fuzz runs, and replays corpus seeds and
deterministic mutations through `fuzz_lib`.
