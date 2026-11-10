# Vendored delharc provenance

- Upstream: `delharc` 0.8.0
- Repository: <https://github.com/royaltm/rust-delharc>
- Tag: `v0.8.0`
- Tag commit: `ea1d90f1febb75e3aa9b53c45f170127074a0fba`
- crates.io checksum: `9cfdcd2bee8dc367afd9064f3b0849156a4c29fc70d98370dae62773594d04dd`
- License: MIT OR Apache-2.0

The source, README, changelog, and both license texts were imported from the published crate.
This local fork retains the upstream version and exposes the library as `delharc`, but uses the publishable package name `libarchive_oxide-delharc` so packaged consumers cannot silently resolve the post-MSRV crates.io source.

Local changes are limited to the project-wide Rust 1.88 MSRV:

- Rust sources and two redundant test expressions are mechanically normalized by the workspace rustfmt and warning-free gates;
- the manifest declares Rust 1.88, omits upstream-only benches/dev tooling, and excludes the Cargo-reserved upstream `Cargo.toml.orig` comparison file from package payloads;
- package documentation names the maintained package rather than the upstream crates.io package and records this fork's Rust 1.88 requirement;
- two match-arm if-let guards are expressed as nested stable conditionals;
- post-MSRV `MaybeUninit::assume_init_mut` calls are replaced by initialized,
  bounds-checked buffers;
- post-MSRV strict-shift and slice-to-array helpers use checked, width-bounded stable expressions; and
- all remaining unchecked assertions and UTF-8 conversions use safe checked operations, with `forbid(unsafe_code)` enforced at the crate root; and
- the crate root limits repository-wide Clippy style policy so published upstream names remain source-compatible.

When updating, import a published upstream crate, verify its tag and crates.io checksum, reapply only the MSRV changes above, run the committed LHA/PMArc corpus, `cargo msrv verify`, `cargo run -p xtask -- codec-policy`, and the full workspace CI suite.
The repository typo gate excludes this upstream snapshot because correcting published identifiers would add unrelated compatibility drift.
The project-specific strict Clippy gate likewise excludes upstream public naming and test style; codec-policy plus the all-feature Rust 1.88 unit/doc gate validate the maintained fork instead.
