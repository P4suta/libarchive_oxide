# SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set shell := ["sh", "-cu"]
set windows-shell := ["powershell.exe", "-NoLogo", "-NoProfile", "-Command"]

export RUSTDOCFLAGS := "-D warnings"

portable_features := "libarchive_oxide/portable-codecs,libarchive_oxide/aes,libarchive_oxide/sevenz,libarchive_oxide/async,libarchive_oxide/tokio,libarchive_oxide-cli/portable-codecs"
native_features := "libarchive_oxide/native-codecs,libarchive_oxide/aes,libarchive_oxide/sevenz,libarchive_oxide/async,libarchive_oxide/tokio,libarchive_oxide-cli/native-codecs"

# List the available development commands.
default:
    @just --list

# Format the workspace.
fmt:
    cargo fmt --all

# Check formatting without modifying files.
fmt-check:
    cargo fmt --all --check

# Run Clippy over both mutually exclusive maximal codec profiles.
lint:
    cargo clippy --workspace --all-targets --no-default-features --features {{portable_features}} -- -D warnings
    cargo clippy --workspace --all-targets --no-default-features --features {{native_features}} -- -D warnings

# Compile Linux-only library code even when the developer host is Windows or macOS.
lint-linux:
    rustup target add x86_64-unknown-linux-gnu
    cargo clippy -p libarchive_oxide --lib --no-default-features --features portable-codecs,async,tokio --target x86_64-unknown-linux-gnu -- -D warnings

# Run the same workspace suite and committed fuzz corpus through both profiles.
test:
    cargo test --workspace --no-default-features --features {{portable_features}}
    cargo test --workspace --no-default-features --features {{native_features}}

# Build public documentation for the default portable profile with warnings denied.
doc:
    cargo doc --workspace --no-default-features --features {{portable_features}} --no-deps

# Spell-check the repository.
typos:
    typos

# Enforce static format and codec dispatch.
no-dyn:
    cargo run --quiet -p xtask -- no-dyn

# Prove that core remains no_std + alloc.
no-std:
    cargo build -p libarchive_oxide-core --target thumbv7em-none-eabi

# Check dependency advisories, bans, licenses, and sources.
deny:
    cargo deny --all-features check advisories bans licenses sources

# Check REUSE/SPDX compliance.
reuse:
    uvx --with charset-normalizer reuse lint

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

# Keep publishing automation manual-only and draft-first.
release-policy:
    cargo run --quiet -p xtask -- release-policy

# Validate GitHub Actions workflows.
actionlint:
    actionlint -color

# Verify the declared core and std MSRVs.
msrv:
    cargo msrv verify --path libarchive_oxide-core
    cargo msrv verify --path libarchive_oxide --no-default-features --features portable-codecs,aes,sevenz,async,tokio
    cargo msrv verify --path libarchive_oxide --no-default-features --features native-codecs,aes,sevenz,async,tokio

# Fast deterministic checks used during the edit/commit loop.
check: fmt-check typos lint lint-linux no-dyn reuse license-sync codec-policy release-policy
    @echo "fast local checks passed"

# Every practical CI gate available on a developer machine.
ci: fmt-check typos lint lint-linux test doc no-dyn no-std deny reuse license-sync package-licenses package-smoke codec-policy release-policy actionlint msrv
    @echo "local CI passed"
