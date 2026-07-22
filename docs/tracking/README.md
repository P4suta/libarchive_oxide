# Modern Replacement issue tracking

The implementation roadmap is tracked with GitHub Issues carrying the
`modern-replacement` label. Every planned unit has a stable `RM-NNN` identifier
so references remain meaningful if titles or issue numbers change.

## Rules

- One issue describes one independently verifiable outcome.
- Epic issues may contain task lists, but implementation work that can merge
  independently gets its own issue.
- “Supported” requires the issue's acceptance criteria and the repository
  support matrix to agree.
- Closing an implementation issue requires test or corpus evidence in the
  completion-evidence section.
- Calendar progress never overrides a Modern Archive Profile completion gate.
- Release execution, version publication, and asset upload are not implied by
  any roadmap issue.

## Stable epics

| ID | Campaign | Epic | Depends on |
|---|---:|---|---|
| [RM-010](https://github.com/P4suta/libarchive_oxide/issues/19) | 0 | Truthful public surface and package validation | none |
| [RM-100](https://github.com/P4suta/libarchive_oxide/issues/20) | 1 | High-level engine, providers, range sources, filesystem contract | RM-010 |
| [RM-110](https://github.com/P4suta/libarchive_oxide/issues/21) | 1 | Portable/native codec profiles and bzip2 | RM-010 |
| [RM-120](https://github.com/P4suta/libarchive_oxide/issues/22) | 1 | Unified `oxarchive` CLI | RM-100 |
| [RM-200](https://github.com/P4suta/libarchive_oxide/issues/23) | 2 | OCI layer engine | RM-100, RM-110 |
| [RM-210](https://github.com/P4suta/libarchive_oxide/issues/24) | 2 | Package profile validators | RM-100, RM-110 |
| [RM-300](https://github.com/P4suta/libarchive_oxide/issues/25) | 3 | Mainstream format depth | RM-100, RM-110 |
| [RM-310](https://github.com/P4suta/libarchive_oxide/issues/26) | 3 | Stable C ABI preview and limited compatibility shim | RM-100 |
| [RM-400](https://github.com/P4suta/libarchive_oxide/issues/27) | 4 | Modern Replacement conformance and 1.0 gates | all prior epics |

Detailed bodies used for initial issue creation live in
[`issue-bodies`](issue-bodies/). New work should use the
“Modern Replacement work item” Issue Form and cite its parent stable ID.

## Implementation units

| ID | Parent | State | Outcome |
|---|---|---|---|
| [RM-101](https://github.com/P4suta/libarchive_oxide/issues/30) | RM-100 | completed by [#31](https://github.com/P4suta/libarchive_oxide/pull/31) | Session-bound inspect, plan, apply, and create engine |
| [RM-102](https://github.com/P4suta/libarchive_oxide/issues/34) | RM-100 | completed by [#35](https://github.com/P4suta/libarchive_oxide/pull/35) | Immutable sync/async range sources over the shared seek parser |
| [RM-103](https://github.com/P4suta/libarchive_oxide/issues/46) | RM-100 | implementation [#49](https://github.com/P4suta/libarchive_oxide/pull/49) | Compile-time format/codec registration and capability queries |
| [RM-104](https://github.com/P4suta/libarchive_oxide/issues/47) | RM-100 | implementation [#50](https://github.com/P4suta/libarchive_oxide/pull/50) | Capability-reporting filesystem contract and Linux adapter |
| [RM-111](https://github.com/P4suta/libarchive_oxide/issues/36) | RM-110 | completed by [#37](https://github.com/P4suta/libarchive_oxide/pull/37) | Pure-Rust bzip2 outer-filter read/write |
| [RM-112](https://github.com/P4suta/libarchive_oxide/issues/38) | RM-110 | completed by [#39](https://github.com/P4suta/libarchive_oxide/pull/39) | Pure-Rust zstd outer-filter read/write |
| [RM-113](https://github.com/P4suta/libarchive_oxide/issues/40) | RM-110 | completed by [#41](https://github.com/P4suta/libarchive_oxide/pull/41) | Pure-Rust LZ4 outer-filter read/write and zstd abort regression |
| [RM-114](https://github.com/P4suta/libarchive_oxide/issues/42) | RM-110 | completed by [#43](https://github.com/P4suta/libarchive_oxide/pull/43) | Pure-Rust XZ/LZMA2 outer-filter read/write |
| [RM-115](https://github.com/P4suta/libarchive_oxide/issues/44) | RM-110 | completed by [#45](https://github.com/P4suta/libarchive_oxide/pull/45) | Default portable and explicit native codec profiles |
| [RM-121](https://github.com/P4suta/libarchive_oxide/issues/32) | RM-120 | completed by [#33](https://github.com/P4suta/libarchive_oxide/pull/33) | `oxarchive` inspect, plan, apply, and verify |
| [RM-122](https://github.com/P4suta/libarchive_oxide/issues/48) | RM-120 | implementation [#51](https://github.com/P4suta/libarchive_oxide/pull/51) | Bounded create, streamed inspection, and unified CLI contracts |
| RM-201 | RM-200 | implementation (DEV-74) | Bounded layer read with one-pass compressed digest and diffID |
| RM-202 | RM-200 | implementation (DEV-74) | Digest-verified layer apply with whiteout, opaque, ownership, link, and conflict handling |
| RM-203 | RM-200 | implementation (DEV-94) | Deterministic OCI layer creation reproducing identical bytes and digests across order, timestamps, ownership, PAX emission, and padding |
| RM-204 | RM-200 | implementation (DEV-95) | Byte/range source adapters feeding the OCI layer engine with no networking, auth, or cloud SDK dependency |
| RM-205 | RM-200 | implementation (DEV-96) | `oxarchive oci` inspect, verify, and apply subcommands over the shared layer engine |
| RM-211 | RM-210 | implementation (DEV-99) | Bounded package-validation framework and Debian `.deb` validator |
| RM-212 | RM-210 | implementation (DEV-100) | Bounded RPM profile validator with no-extract lead/header parsing and compressed cpio payload checks |

The cross-epic acceptance mapping, local reproductions, performance/RSS data,
and remote-only gates are collected in the
[Campaign 1 completion evidence](campaign-1-evidence.md) and the
[Campaign 2 completion evidence](campaign-2-evidence.md).

## Labels

- `modern-replacement`: part of the gated replacement roadmap.
- `campaign:0` through `campaign:4`: earliest campaign that owns the result.
- `epic`: a tracking issue whose checklist links independently closable work.
- `completion-gate`: evidence required before the Modern Replacement claim.
- `area:engine`, `area:codec`, `area:cli`, `area:oci`, `area:package`,
  `area:format`, `area:c-abi`, and `area:conformance`: technical ownership.
