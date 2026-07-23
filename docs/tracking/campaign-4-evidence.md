# Campaign 4 final-gate evidence audit

This snapshot is an **evidence audit only** of the RM-400 (DEV-78) Campaign 4
final completion gate for the Modern Replacement claim. It does not close, tag,
or advance anything. Per the roadmap decision rule, *calendar progress never
overrides a completion gate* and *capability honesty is necessary but not
sufficient* (ADR-0012), so a checkbox flips only when its own durable evidence
exists — never by date, version, or the presence of neighboring green gates.
The RM-400 issue does not authorize release execution; that remains a separate,
explicitly manual maintainer decision.

No tag, package publication, GitHub Release, release-workflow execution, version
change, or versioned release candidate is described, proposed, or implied by this
snapshot. It records the current state of each required-evidence checkbox against
the CI defined in `.github/workflows/ci.yml` and the roadmap state in
`docs/tracking/README.md`, so the gate's true state is legible.

DEV-78 (RM-400) is **blockedBy DEV-124**. DEV-124 was the root fix of the flaky
async/filter codec hang (the portable XZ worker-thread deadlock in
`filter/xz.rs`, exercised by `async_stream_v2.rs`; RM-114 XZ-in-pure-Rust
lineage) that intermittently stalled the `big-endian (s390x, qemu)`,
`test (macos-latest)`, and `test (ubuntu-latest)` jobs to a `timeout-minutes`
kill. **DEV-124 has since landed on `main` (#70)**, so checkbox 9's flaky
blocker on the axes CI already exercises is resolved *pending durable
multi-run confirmation* (the acceptance's ≥20 hang-free CI reps); the deterministic
`async_xz_never_deadlocks_under_slow_source` regression test now guards it. The
remaining checkbox-9 gaps are structural (no WASI / 32-bit axes), not flaky — see
the checkbox-9 row below.

## Audit method

The RM-400 issue body (`docs/tracking/issue-bodies/RM-400.md`) carries **ten**
required-evidence checkboxes under "Required evidence" (the task brief referred
to 11; the extra item is the bundled API / C-ABI / CLI-exit-code / support-matrix
freeze in checkbox 4, which this audit breaks into its four sub-freezes below).
Each checkbox is marked **present** (durable evidence exists and a gate enforces
it), **partial** (evidence exists for some but not all of the checkbox's scope,
or a gate exists but is dormant/absent for part of it), or **not started** (no
evidence and no enforcing gate yet). The concrete source (CI job, xtask gate,
ADR, or roadmap unit) is named for every verdict.

## Checkbox audit

### 1. Portable Tier 1 codec profile is C/FFI-free by dependency-graph proof — **present**

- Enforced every CI run by the `license-sync` job step *"verify portable
  exclusion and explicit native codec backends"* → `just codec-policy` →
  `xtask` `check_codec_policy` (`xtask/src/main.rs`), which mechanically proves
  the portable profile excludes C/FFI codec backends and that native backends
  are explicit.
- `deny` job (`cargo-deny` advisories/licenses/bans/sources) backstops the
  dependency graph. ADR-0005 (codec profiles) and ADR-0012 (codec-capability
  contract) fix the C-free portable guarantee as a non-negotiable core property.
- `docs/support-matrix.md` records the C-free portable profile as a core
  guarantee. Verdict: **evidence present**, gate-enforced on every push/PR.

### 2. Primary read/write and compatibility read-only format profiles pass their exact matrices — **partial**

- Primary read+write formats (ZIP, 7z, tar, cpio, ar, ISO) and the first
  read-only compatibility providers (CAB, XAR — RM-305) are implemented and
  covered by the `test` matrix job (conformance + committed corpus on the
  portable and native profiles across ubuntu/windows/macOS). The grid
  support-matrix (method × read/write × portable/native) landed in RM-307.
- Not yet complete / not frozen: Deflate64 (method 9) is unimplemented (tracked
  deficit, RM-306/ADR-0013); RAR5 and UDF are deferred/feasibility-only
  (ADR-0013); the matrices are still evolving, not declared final. Verdict:
  **partial** — matrices exist and pass for implemented cells, but coverage is
  incomplete and unfrozen.

### 3. OCI and package conformance profiles pass — **present**

- OCI (RM-200 → RM-201..205, DEV-92..96) and package validators (RM-210 →
  RM-211..215, DEV-99..103) are all implemented and Done at the unit level; the
  `test` job runs `oci_layer`/`oci_create`/`oci_range`/`oci_cli` and
  `package_deb`/`package_rpm`/`package_zip`/`package_app`/`package_cli` suites
  green (see `campaign-2-evidence.md`). Verdict: **evidence present** at the
  technical-gate level. (The parent epics still await required remote checks and
  `main`; the 10 GiB soak is tracked separately as checkbox 7.)

### 4. Stable Rust API, C ABI, CLI exit-code contract, and support matrix are frozen and checked — **partial**

Broken into its four bundled sub-freezes:

- **Rust API freeze** — *partial / dormant.* The `semver-checks` job exists but
  is gated off (`if: vars.V02_BASELINE_PUBLISHED == 'true'`); it prints a
  bootstrap-skip notice until a v0.2 crates.io baseline is established, so no
  API-compat gate is currently enforced on PRs. No "frozen" declaration exists.
- **C ABI freeze** — *not started.* RM-310 (Campaign 3 epic: stable C ABI +
  limited compat shim) has **all acceptance checkboxes unchecked**; there is no
  `libarchive_oxide-c` crate, no generated `archive_oxide.h`, and no C11/C++17
  header-harness, symbol/struct snapshot, Miri, or ABI-fuzz job in `ci.yml`.
- **CLI exit-code contract** — *present.* RM-121/RM-122/RM-205/RM-215 CLI
  contract suites assert the exit-0/1/2 usage contract (`oci_cli`,
  `package_cli`), run in the `test` job.
- **Support matrix checked** — *partial.* `docs/support-matrix.md` exists as the
  RM-307 accountability grid and is reconciled with acceptance criteria by
  policy (README rule: "Supported requires acceptance and the support matrix to
  agree"), but it is not machine-frozen and is still changing per slice.

Verdict: **partial** — CLI exit codes present; support matrix present-but-unfrozen;
Rust API gate dormant; C ABI not started (RM-310).

### 5. Three-producer/two-consumer interoperability evidence exists per format/method — **partial**

- The RM-301 interop-evidence harness (ADR-0011) plus RM-302 (ZIP BZip2/Zstd/
  LZMA), RM-304 (tar/cpio/ar/ISO metadata fidelity), RM-305 (CAB/XAR), and
  RM-308 (ZIP extra fields) provide 3-producer/2-consumer evidence for many
  format/methods, run in the `test` job over `interop_*` suites.
- Honest gaps recorded in `campaign-3-evidence.md`: ISO producer independence is
  narrower (arca self round-trip + external mastering tool with graceful skip,
  no pure-Rust independent reader); cpio's third producer is a second first-party
  dialect builder (no mature pure-Rust cpio producer crate); ZIP LZMA leans on a
  committed liblzma fixture as its sole independent codec. 7z coder-graph depth
  (multi-folder, BCJ/Delta, Deflate/BZip2/Zstd, AES-256) has since landed on
  `main` via RM-303 (#71) with 3-producer differential evidence against
  `sevenz-rust2`, though PPMd and BCJ2 stay deferred (ADR-0012). Not universal
  across every format/method. Verdict: **partial**.

### 6. Malformed, fuzz, resource-arithmetic, symlink-race, and decompression-bomb gates pass — **present**

- `fuzz` job (nightly, cargo-fuzz): panic-abort regression replay + bounded
  campaign over the committed corpus on portable and native, with
  `RUSTFLAGS: -C overflow-checks=yes` keeping malformed length **arithmetic**
  fail-closed (`xtask fuzz-ci`).
- Decompression bombs bounded by `Limits::decoded_total` throughout (ZIP/7z/CAB/
  XAR/OCI/package suites; e.g. `*_bomb_is_bounded_by_limits`,
  `decompression_bomb_is_bounded`). Symlink-race / traversal / symlink-escape
  covered by the capability filesystem (ADR-0007) and RM-202 apply tests
  (`plan_rejects_entries_escaping_through_a_layer_symlink`,
  `plan_rejects_traversal_and_duplicate_paths`). Malformed/truncated inputs
  return structured errors across all provider suites. Verdict: **present**.

### 7. 10 GiB streaming soak stays within the documented RSS budget — **not started**

- Explicitly recorded as out of scope for the RM-200 slices
  (`campaign-2-evidence.md`: "Only a full 10 GiB soak remains out of scope").
  No soak job exists in `ci.yml` and no documented RSS budget number is asserted
  by a gate. Verdict: **not started** (remaining task).

### 8. Native and portable performance gates pass without unapproved sustained regressions — **partial**

- Baseline performance / RSS data is collected in the Campaign 1 completion
  evidence (referenced from `docs/tracking/README.md`). However, **no automated
  performance-regression gate is wired into `ci.yml`** — there is no benchmark
  job comparing native vs portable throughput against a baseline with an
  approval mechanism for sustained regressions. Verdict: **partial** — baseline
  data exists; the enforcing gate does not.

### 9. Portable/native, no_std, WASI inspection, big-endian, 32-bit, MSRV, and all-features CI pass — **partial** (DEV-124 blocker)

- Covered by CI: **portable/native** (`test` job runs both profiles across
  ubuntu/windows/macOS), **no_std** (`no_std` job, thumbv7em-none-eabi),
  **big-endian** (`big-endian` job, s390x under qemu), **MSRV** (`msrv` job,
  core 1.85 / flagship 1.87), and the maximal-features profiles inside `test`.
- **Absent axes:** there is **no WASI-inspection job** and **no 32-bit target
  job** in `ci.yml` — those two axes are not started.
- **DEV-124 blocker (now resolved on `main`):** DEV-78 is blockedBy DEV-124,
  which removed the flaky async/filter codec hang that intermittently timed out
  the `big-endian`, `test (macos-latest)`, and `test (ubuntu-latest)` jobs.
  DEV-124's deterministic root fix has **landed (#70)** — the worker-thread
  wakeup deadlock in `filter/xz.rs` is fixed and guarded by
  `async_xz_never_deadlocks_under_slow_source`, replacing the old
  re-run-the-job (`gh run rerun <id> --failed`) workaround. The covered axes can
  now be declared durably green *once* the acceptance's sustained ≥20 hang-free CI
  reps are recorded; that confirmation is the only remaining item for the covered
  axes. Verdict: **partial** — the flaky blocker is cleared, but WASI-inspection
  and 32-bit axes are still not-started and the ≥20-rep durability record is pending.

### 10. At least two release candidates complete all technical gates — **not started**

- No release candidate exists; RC evidence is impossible until every preceding
  checkbox is durably green, and RC/tag/release execution is deliberately out of
  scope for this audit and for the roadmap issue. Verdict: **not started**
  (remaining task).

## Still-open checkboxes (remaining tasks for the gate's true state)

- **Checkbox 2** — format-matrix completeness: Deflate64 (method 9) read still
  to be wired (RM-306/ADR-0013); RAR5/UDF remain deferred/feasibility-only.
- **Checkbox 4** — C ABI freeze = **RM-310 not started** (no `libarchive_oxide-c`
  crate, no header harness, no ABI snapshot/Miri/ABI-fuzz CI); Rust API
  `semver-checks` gate dormant until a v0.2 baseline exists; support matrix not
  machine-frozen.
- **Checkbox 5** — three-producer/two-consumer completeness is not yet universal
  per format/method (ISO/cpio/7z gaps noted).
- **Checkbox 7** — the 10 GiB streaming soak against a documented RSS budget is
  not yet run or gated.
- **Checkbox 8** — no CI performance-regression gate exists (only Campaign 1
  baseline data).
- **Checkbox 9** — WASI-inspection and 32-bit CI axes are absent; the DEV-124
  flaky-hang root fix has landed (#70), so the covered axes now need only the
  acceptance's sustained ≥20 hang-free CI reps recorded as durable evidence.
- **Checkbox 10** — ≥2 release candidates completing all technical gates: not
  started, and downstream of every item above.

## Status tally

- **Present: 3** — checkboxes 1, 3, 6.
- **Partial: 5** — checkboxes 2, 4, 5, 8, 9.
- **Not started: 2** — checkboxes 7, 10.

Ten required-evidence checkboxes: **3 present / 5 partial / 2 not started**. The
final gate is **not** met; no checkbox may be overridden by date or version. The
DEV-124 root fix has landed (#70), clearing checkbox 9's flaky blocker; the
covered CI axes still need the acceptance's sustained ≥20 hang-free reps recorded
before they count as durably green. This document is an audit snapshot only — it
closes nothing.
