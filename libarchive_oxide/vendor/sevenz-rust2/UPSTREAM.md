# Vendored sevenz-rust2 provenance

- Upstream: `sevenz-rust2` 0.21.3
- Repository: <https://github.com/hasenbanck/sevenz-rust2>
- Tag: `v0.21.3`
- Tag commit: `e5d33dbe62c698d71ecd31f705de0e5a9fc45520`
- crates.io checksum: `0b5d71c87d24cb22976f3f6e6c2c9296ef1f6958394e2b868d56ca01b082798a`
- License: Apache-2.0

The source, README, changelog, rustfmt configuration, and license text were imported from the published crate.
The fork remains a dev-only independent 7z producer/consumer and retains the upstream package version.

Local changes are limited to the workspace's Rust 1.88 and Safe Rust policies:

- the manifest declares Rust 1.88 and omits upstream examples, integration fixtures, and dev tooling;
- optional `nt-time` 0.15 is pinned to API-compatible `nt-time` 0.13.0, whose declared MSRV is Rust 1.85; the project does not enable this optional feature;
- the crate root explicitly forbids unsafe code and limits repository-wide Clippy style policy so published upstream names remain source-compatible; and
- source is normalized by the committed upstream rustfmt configuration.

When updating, import a published upstream crate, verify its tag and crates.io checksum, preserve an all-feature Rust 1.88 build, run the full differential 7z suite, `cargo msrv verify`, `cargo run -p xtask -- codec-policy`, and workspace CI.
The repository typo gate excludes this upstream snapshot because correcting published identifiers would add unrelated compatibility drift.
The project-specific strict Clippy gate likewise excludes upstream public naming and test style; codec-policy plus the all-feature Rust 1.88 check validate the maintained fork instead.
