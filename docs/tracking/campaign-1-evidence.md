# Campaign 1 completion evidence

This snapshot records the technical evidence for RM-100, RM-110, and RM-120.
It is based on main `7a48c73` plus the stacked implementation PRs listed
below. The parent epics close only after every PR has passed its required
remote checks and reached `main`.

No tag, package publication, GitHub Release, release-workflow execution,
version change, or versioned release candidate is part of this snapshot.

## Implementation map

| Work | Issue | Pull request | Evidence |
|---|---:|---:|---|
| Session-bound engine | #30 | #31 | inspect/event, plan identity, apply, and create tests |
| Immutable range sources | #34 | #35 | sync/async identity and bounded cache tests |
| Compile-time providers | #46 | #49 | static registration, probing, capabilities, shared state, package consumer |
| Capability filesystem | #47 | #50 | typed findings, race/identity failure, Linux fidelity, atomic commit |
| Pure-Rust bzip2 | #36 | #37 | shared boundary, malformed, differential, and writer tests |
| Pure-Rust zstd | #38 | #39 | shared boundary, malformed, differential, and writer tests |
| Pure-Rust LZ4 | #40 | #41 | linked blocks, truncation, deterministic writer, terminal zstd regression |
| Pure-Rust XZ/LZMA2 | #42 | #43 | dictionary/index bounds, concatenation, async and interoperability tests |
| Codec profiles | #44 | #45 | portable dependency exclusion, native selection, shared corpus, benchmark/RSS |
| Initial unified CLI | #32 | #33 | inspect, plan, apply, verify, and compatibility-binary contracts |
| Bounded create/CLI | #48 | #51 | create, streamed JSON Lines, atomic output, exit/stdout/stderr contracts |

## RM-100

- ADR-0003, ADR-0004, ADR-0006, and ADR-0007 specify session identity,
  ranges, compile-time providers, and capability-reporting filesystems.
- `engine`, `providers`, `range_source`, and `filesystem_adapter` cover
  collected and event inspection limits, plan replay/mismatch, shared parser
  state, adapter capability queries, partial failure, destination races, and
  atomic publication.
- The Linux reference test restores mode, timestamps, xattrs, POSIX ACLs, and
  sparse layout; link behavior and unsafe paths have dedicated extraction and
  adapter tests.
- Current readers, writers, and `Pipeline` remain documented low-level APIs.

## RM-110

- ADR-0005 and `codec-profiles.md` define mutually exclusive default portable
  and explicit native profiles.
- `xtask codec-policy` rejects native codec packages in the portable graph and
  requires all five native backends in the native graph.
- Both profiles run the same sync, Pipeline, futures, Tokio, CLI,
  malformed-input, committed corpus, and differential tests.
- The recorded 16 MiB comparison and 64 MiB scaling run cover every codec.
  Peak additional RSS remained 10.2 MiB or less.

## RM-120

- ADR-0008 and `cli-contract.md` specify shared-engine creation, bounded
  inspection, atomic/no-replace file output, standard-stream partial output,
  JSON Lines completion, and exit status 0/1/2.
- JSON records carry `oxarchive.output.v0alpha1`; a late parser error leaves
  valid preceding records but no completion record.
- Contract tests exercise all five binaries, four create formats, outer
  filters, stdin/stdout, unsafe paths, existing destinations, and early and
  late failures.

## Reproduced gates

- Final stacked tree, Windows x86_64, Rust 1.97.1: portable and native
  workspace suites completed together in 93.2 seconds.
- The manual generated 10 GiB archive soak completed in 4.34 seconds after
  the release build and never emitted a chunk larger than 64 KiB.
- The Linux Bookworm filesystem-adapter suite passed 7/7, including the
  fidelity test.
- Host portable/native workspace Clippy and Linux-target library Clippy pass
  with warnings denied. Lefthook runs both before every Rust commit.
- Rustfmt, rustdoc, MSRV 1.85/1.87, no-std core, semver checks, package smoke,
  codec/dependency policy, cargo-deny, REUSE, typos, and actionlint pass.
- PRs #49, #50, and #51 are the immutable remote evidence for the
  Linux/macOS/Windows matrix, nightly panic-abort/libFuzzer campaign,
  s390x/QEMU big-endian suite, and CodeQL. An epic is not complete while one
  of those required checks is pending or failed.
