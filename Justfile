# SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set shell := ["sh", "-cu"]
set windows-shell := ["powershell.exe", "-NoLogo", "-NoProfile", "-Command"]

export RUSTDOCFLAGS := "-D warnings"

# List the available development commands.
default:
    @just --list

# Format the workspace.
fmt:
    cargo fmt --all

# Check formatting without modifying files.
fmt-check:
    cargo fmt --all --check

# Run Clippy over every target and feature.
lint:
    cargo clippy --workspace --all-targets --all-features -- -D warnings

# Run the portable workspace test suite.
test:
    cargo test --workspace --all-features

# Build public documentation with warnings denied.
doc:
    cargo doc --workspace --all-features --no-deps

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

# Keep the bzip2, zstd, and LZ4 Tier 1 paths on their Rust implementations.
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
    cargo msrv verify --path libarchive_oxide --all-features

# Fast deterministic checks used during the edit/commit loop.
check: fmt-check typos lint no-dyn reuse license-sync codec-policy release-policy
    @echo "fast local checks passed"

# Every practical CI gate available on a developer machine.
ci: fmt-check typos lint test doc no-dyn no-std deny reuse license-sync package-licenses package-smoke codec-policy release-policy actionlint msrv
    @echo "local CI passed"
