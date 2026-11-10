# SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set shell := ["sh", "-cu"]
set windows-shell := ["powershell.exe", "-NoLogo", "-NoProfile", "-Command"]

export RUSTDOCFLAGS := "-D warnings"

portable_features := "libarchive_oxide/portable-codecs,libarchive_oxide/aes,libarchive_oxide/sevenz,libarchive_oxide/async,libarchive_oxide/tokio,libarchive_oxide-cli/portable-codecs"
native_features := "libarchive_oxide/native-codecs,libarchive_oxide/aes,libarchive_oxide/sevenz,libarchive_oxide/async,libarchive_oxide/tokio,libarchive_oxide-cli/native-codecs"
nextest_filter := "not binary(fuzz_replay)"
fuzz_test_threads := env_var_or_default("RUST_TEST_THREADS", "4")

# List the available development commands.
default:
    @just --list

# Format the workspace.
fmt:
    cargo fmt --all

# Check formatting without modifying files.
fmt-check:
    cargo fmt --all --check

# Run project-owned crates through the repository's strict Clippy policy. The
# maintained upstream snapshots have their own MSRV/unit/doc policy below;
# applying local naming/style lints would mutate published compatibility APIs.
lint:
    cargo clippy --workspace --exclude libarchive_oxide-delharc --exclude sevenz-rust2 --all-targets --no-default-features --features {{ portable_features }} -- -D warnings
    cargo clippy --workspace --exclude libarchive_oxide-delharc --exclude sevenz-rust2 --all-targets --no-default-features --features {{ native_features }} -- -D warnings

# Lint the portable workspace used for ordinary changes.
lint-portable:
    cargo clippy --locked --workspace --all-targets --no-default-features --features {{ portable_features }} -- -D warnings

# Compile Linux-only library code even when the developer host is Windows or macOS.
lint-linux:
    rustup target add x86_64-unknown-linux-gnu
    cargo clippy -p libarchive_oxide --lib --no-default-features --features portable-codecs,async,tokio --target x86_64-unknown-linux-gnu -- -D warnings

# Compile macOS-only library code even when the developer host is Windows or Linux.
lint-macos:
    rustup target add aarch64-apple-darwin
    cargo clippy -p libarchive_oxide --lib --no-default-features --features portable-codecs,async,tokio --target aarch64-apple-darwin -- -D warnings

# Run the same workspace suite and committed fuzz corpus through both profiles.
# Nextest runs ordinary tests process-per-test; the corpus gets one optimized
# process per profile. Cargo separately runs doctests, which nextest cannot.
test: fuzz-replay
    cargo nextest run --workspace --no-default-features --features {{ portable_features }} -E '{{ nextest_filter }}'
    cargo test --workspace --doc --no-default-features --features {{ portable_features }}
    cargo nextest run --workspace --no-default-features --features {{ native_features }} -E '{{ nextest_filter }}'
    cargo test --workspace --doc --no-default-features --features {{ native_features }}

# Run the complete test suite with the non-fail-fast CI profile.
test-ci: fuzz-replay
    cargo nextest run --profile ci --workspace --no-default-features --features {{ portable_features }} -E '{{ nextest_filter }}'
    cargo test --workspace --doc --no-default-features --features {{ portable_features }}
    cargo nextest run --profile ci --workspace --no-default-features --features {{ native_features }} -E '{{ nextest_filter }}'
    cargo test --workspace --doc --no-default-features --features {{ native_features }}

# Run portable regressions and doctests without a platform or codec matrix.
test-portable:
    cargo test --release --locked -p libarchive_oxide --test fuzz_replay --no-default-features --features portable-codecs,aes,sevenz,async,tokio -- --test-threads={{ fuzz_test_threads }}
    cargo nextest run --locked --profile ci --workspace --no-default-features --features {{ portable_features }} -E '{{ nextest_filter }}'
    cargo test --locked --workspace --doc --no-default-features --features {{ portable_features }}

# Run every committed corpus mutation in one optimized process per codec
# profile. This preserves the full portable/native replay in every test loop,
# while avoiding nextest's process-per-test fixture reload. Bound local
# parallelism as well: the LHA/XZ/package shards are CPU-heavy, and allowing a
# high-core-count host to launch all of them at once is substantially slower.
fuzz-replay:
    cargo test --release -p libarchive_oxide --test fuzz_replay --no-default-features --features portable-codecs,aes,sevenz,async,tokio -- --test-threads={{ fuzz_test_threads }}
    cargo test --release -p libarchive_oxide --test fuzz_replay --no-default-features --features native-codecs,aes,sevenz,async,tokio -- --test-threads={{ fuzz_test_threads }}

# Stream logical 10 GiB tar/gzip/xz/zstd archives without materializing them.
# Separate test processes make Linux's peak-RSS <= 128 MiB verdict codec-specific.
streaming-soak:
    cargo test --release -p libarchive_oxide --test large_stream_v2 --no-default-features --features gzip,xz,zstd generated_10_gib_archive_streams_without_size_proportional_allocation -- --exact --ignored --nocapture
    cargo test --release -p libarchive_oxide --test large_stream_v2 --no-default-features --features gzip,xz,zstd generated_10_gib_gzip_tar_streams_without_size_proportional_allocation -- --exact --ignored --nocapture
    cargo test --release -p libarchive_oxide --test large_stream_v2 --no-default-features --features gzip,xz,zstd generated_10_gib_xz_tar_streams_without_size_proportional_allocation -- --exact --ignored --nocapture
    cargo test --release -p libarchive_oxide --test large_stream_v2 --no-default-features --features gzip,xz,zstd generated_10_gib_zstd_tar_streams_without_size_proportional_allocation -- --exact --ignored --nocapture

# Compile every individual feature, every minimal positive feature conjunction
# found in facade #[cfg(...)] attributes, and the combined maximal profile. The
# xtask removes feature implications before running seam cells, so aggregate
# profiles do not rebuild equivalent configurations. Source-derived seams catch
# new interactions without restoring an unrelated quadratic powerset.
feature-matrix:
    cargo run --quiet -p xtask -- feature-matrix

# Build public documentation for both maximal codec profiles with warnings denied.
doc:
    cargo doc --workspace --no-default-features --features {{ portable_features }} --no-deps
    cargo doc --workspace --no-default-features --features {{ native_features }} --no-deps

# Cross-check both maximal profiles on 32-bit Windows.
check-32-bit-windows:
    rustup target add i686-pc-windows-msvc
    cargo check --workspace --all-targets --no-default-features --features {{ portable_features }} --target i686-pc-windows-msvc
    cargo check --workspace --all-targets --no-default-features --features {{ native_features }} --target i686-pc-windows-msvc

# Compile the inspection stack for WASI without filesystem extraction, native
# libraries, async runtimes, or platform-specific adapters.
wasi:
    rustup target add wasm32-wasip1
    cargo check -p libarchive_oxide-protocol --target wasm32-wasip1
    cargo check -p libarchive_oxide-core --target wasm32-wasip1
    cargo check -p libarchive_oxide-codecs --target wasm32-wasip1 --all-features
    cargo check -p libarchive_oxide-ppmd --target wasm32-wasip1
    cargo check -p libarchive_oxide-rar-crypto --target wasm32-wasip1
    cargo check -p libarchive_oxide-rarvm --target wasm32-wasip1
    cargo check -p libarchive_oxide-rar --target wasm32-wasip1
    cargo check -p libarchive_oxide --lib --target wasm32-wasip1 --no-default-features --features portable-codecs

# Spell-check the repository.
typos:
    typos

# Exercise downstream static format/codec providers through the shared pipeline.
provider-conformance:
    cargo test -p libarchive_oxide --test providers --all-features static_provider_chains

# Preserve the existing qualification workflow entry point.
registry: provider-conformance architecture

# Enforce the crate dependency direction and the format/codec sibling boundary.
architecture:
    cargo run --quiet -p xtask -- architecture

# Keep expensive corpus mutations automatic without process-per-test contention.
ci-efficiency:
    cargo run --quiet -p xtask -- ci-efficiency

# Prove that protocol, core, and every portable codec remain no_std + alloc.
no-std:
    cargo build -p libarchive_oxide-protocol --target thumbv7em-none-eabi
    cargo build -p libarchive_oxide-core --target thumbv7em-none-eabi
    cargo build -p libarchive_oxide-codecs --target thumbv7em-none-eabi --all-features
    cargo build -p libarchive_oxide-ppmd --target thumbv7em-none-eabi
    cargo build -p libarchive_oxide-rar-crypto --target thumbv7em-none-eabi
    cargo build -p libarchive_oxide-rarvm --target thumbv7em-none-eabi
    cargo build -p libarchive_oxide-rar --target thumbv7em-none-eabi

# Check dependency advisories, bans, licenses, and sources.
deny:
    cargo deny --all-features check advisories bans licenses sources

# Reject unused, misplaced, and unlinked Cargo dependencies or source files.
shear:
    cargo shear --deny-warnings

# Check REUSE/SPDX compliance.
reuse:
    uvx --with charset-normalizer==3.4.9 reuse==6.2.0 lint

# Check canonical license copies.
license-sync:
    cargo run --quiet -p xtask -- license-sync

# Check packaged license files.
package-licenses:
    cargo run --quiet -p xtask -- package-licenses

# Build the exact packaged sources in a fresh external consumer workspace.
package-smoke:
    cargo run --quiet -p xtask -- package-smoke

# Verify portable C/FFI exclusion and explicit native backend selection.
codec-policy:
    cargo run --quiet -p xtask -- codec-policy

# Verify the support matrix was generated from the canonical capability ledger.
capability-docs:
    cargo run --quiet -p xtask -- capability-docs

# Regenerate the support matrix from the canonical capability ledger.
capability-docs-write:
    cargo run --quiet -p xtask -- capability-docs-write

# Keep the completion-phase version fixed and publishing manual-only/draft-first.
release-policy:
    cargo run --quiet -p xtask -- release-policy

# Run the bounded nightly panic-abort and libFuzzer campaign (requires FUZZ_TARGET).
fuzz-ci:
    cargo run --quiet -p xtask -- fuzz-ci

# Compile and run the bounded s390x test selection through cross/qemu.
big-endian-ci:
    cargo run --quiet -p xtask -- big-endian-ci-compile
    cargo run --quiet -p xtask -- big-endian-ci

# Validate GitHub Actions workflows.
actionlint:
    actionlint -color

# Reject high-severity GitHub Actions and Dependabot security findings without
# granting the auditor network or repository credentials.
zizmor:
    zizmor --offline --persona regular --min-severity high .

# Verify every workspace crate at the shared declared MSRV.
msrv:
    cargo msrv verify --path libarchive_oxide-protocol
    cargo msrv verify --path libarchive_oxide-core
    cargo msrv verify --path libarchive_oxide-codecs --all-features
    cargo msrv verify --path libarchive_oxide-ppmd
    cargo msrv verify --path libarchive_oxide-rarvm
    cargo msrv verify --path libarchive_oxide-rar-crypto
    cargo msrv verify --path libarchive_oxide-rar
    cargo msrv verify --path libarchive_oxide --no-default-features --features portable-codecs,aes,sevenz,async,tokio
    cargo msrv verify --path libarchive_oxide --no-default-features --features native-codecs,aes,sevenz,async,tokio
    cargo msrv verify --path libarchive_oxide-package --no-default-features --features portable-codecs
    cargo msrv verify --path libarchive_oxide-cli --no-default-features --features portable-codecs
    cargo msrv verify --path xtask
    rustup target add --toolchain 1.95.0 thumbv7em-none-eabi
    cargo msrv verify --path libarchive_oxide-core --target thumbv7em-none-eabi
    cargo msrv verify --path libarchive_oxide-codecs --all-features --target thumbv7em-none-eabi

# Exercise both locally maintained upstream forks on the workspace MSRV.
# Include optional surfaces not enabled by the flagship crate.
vendor-msrv:
    cargo fmt --manifest-path libarchive_oxide/vendor/delharc/Cargo.toml --all -- --check
    cargo fmt --manifest-path libarchive_oxide/vendor/sevenz-rust2/Cargo.toml --all -- --check
    cargo +1.95.0 test --manifest-path libarchive_oxide/vendor/delharc/Cargo.toml --all-features
    cargo +1.95.0 check --manifest-path libarchive_oxide/vendor/sevenz-rust2/Cargo.toml --all-features

# Fast deterministic checks used during the edit/commit loop.
check: fmt-check typos lint-portable shear reuse license-sync architecture ci-efficiency codec-policy capability-docs release-policy actionlint zizmor
    @echo "fast local checks passed"

# Verify ordinary changes through the same gate as pull requests.
ci: check test-portable deny
    @echo "local CI passed"

# Run the complete checks supported on a developer machine before a release.
release-check: fmt-check typos lint lint-linux lint-macos feature-matrix test-ci streaming-soak doc provider-conformance architecture no-std wasi deny shear reuse license-sync package-licenses package-smoke codec-policy capability-docs release-policy actionlint zizmor msrv
    @echo "local release checks passed"
