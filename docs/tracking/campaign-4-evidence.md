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
remaining checkbox-9 structural gap is WASI inspection; the 32-bit
portable/native compile axis is now a required Windows CI job. The covered axes
still need the acceptance's durable multi-run record — see the checkbox-9 row
below.

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

- Primary read+write formats (ZIP, 7z, tar, cpio, ar, ISO) and the
  read-only compatibility providers (CAB, XAR, and UDF) are implemented and
  covered by the `test` matrix job (conformance + committed corpus on the
  portable and native profiles across ubuntu/windows/macOS). The grid
  support-matrix (method × read/write × portable/native) landed in RM-307.
- Deflate64 method 9 read and the UDF 1.02–2.60 provider, including
  continued File Set Descriptors, UDF 2.01 named/system streams, and bounded
  UDF 2.50/2.60 Metadata Partition translation/mirror recovery plus UDF
  1.50+ Sparable Partition packet remapping/Metadata-over-Sparable and UDF
  1.50/2.00+ Virtual Partition/VAT translation, are now implemented and run
  through the same portable/native and seek-adapter matrices. UDF fixtures
  cover default file-set-zero selection, FID
  order/version/long-ad identity, Stream/metadata flags, and aggregate EFE
  Object Size. Metadata fixtures additionally cover allocation-unit boundaries,
  auxiliary ICB types, cycles/overlap, descriptor corruption, mirror fallback,
  and limits. Virtual fixtures cover old/new VAT layouts, direct short/long
  and continued split physical allocations, bounded history, map constraints,
  malformed/truncated/cyclic/overlapping VATs, and limits. Sparable fixtures
  cover profile-valid 16/32-block packets, packet-disjoint redundant-table
  sequence selection and corruption fallback, the 65,535-byte descriptor-CRC
  cap, packet-boundary remapping, table/map/range corruption, exact
  capacity-based cumulative metadata limits, and an independent `mkudffs` 2.3
  image. RAR5 remains
  deliberately deferred. The matrices are still
  evolving and are not
  declared final. Verdict:
  **partial** — implemented cells pass, but external-producer coverage and
  matrix freeze remain incomplete.

### 3. OCI and package conformance profiles pass — **structural profiles present; authenticity partial**

- OCI (RM-200 → RM-201..205, DEV-92..96) and package validators (RM-210 →
  RM-211..215, DEV-99..103) have bounded structural profiles; the
  `test` job runs `oci_layer`/`oci_create`/`oci_range`/`oci_cli` and
  `package_deb`/`package_rpm`/`package_zip`/`package_app`/`package_cli` suites
  (see `campaign-2-evidence.md`).
- Authenticity is not complete merely because every ecosystem has a structural
  validator. JAR/APK v1 exact manifest/main/section digests and every CMS
  signer, Android APK v2/v3, Alpine RSA, RPM payload digests, Wheel `RECORD`,
  and MSIX `AppxBlockMap.xml` integrity have cryptographic checks. APK v1
  multi-signer coverage and v1/v2/v3 combined failure semantics are exercised
  with OpenJDK and official AOSP fixtures. NuGet v1 author/repository CMS
  signatures, repository
  countersignatures, and canonical package hashes are also checked offline
  against an official NuGet.org fixture. APK v4/v4.1 detached sidecars now
  have bounded offline verification of every signing info, v2/v3/v3.1 exact
  certificate-and-digest binding, the fs-verity-compatible SHA-256 Merkle
  root/tree, explicit trust pins, and versioned CLI JSON. Official CTS and
  `apksig` v4.0/v4.1 positive pairs, AOSP's v3.1 digest-mismatch negative pair,
  tampering, wrong-APK, unknown-algorithm, resource-limit, and no-sidecar
  scenarios run in `package_android_v4_signature` and `package_cli`. RPM
  package signatures, Wheel `RECORD.jws`/`RECORD.p7s`, IPA signing, MSIX
  `AppxSignature.p7x`, and Android binary-manifest/per-platform installability
  semantics remain unverified or explicitly unsupported. APK v3/v3.1
  proof-of-rotation, targeted signer ranges, stripping protection, and
  standard/fs-verity content-digest combinations are now verified separately
  from trust with official AOSP positive and negative fixtures.
- Verdict: **structural conformance present; authenticity partial**. Integrity,
  signature validity, and issuer trust remain separate and `not-evaluated`
  never counts as success.

### 4. Evolving Rust API, CLI exit-code/JSON contract, and support matrix are checked — **in-scope portions present**

Broken into its four bundled sub-freezes:

- **Rust API freeze** — *deliberately outside the continuation program.* The
  library remains pre-freeze while breaking changes are used to converge on the
  Rust-first design; no SemVer-compatibility job is a required gate.
- **C ABI freeze** — *deliberately outside the continuation program.* A C ABI is
  not part of this project and would be designed as a separate project if it is
  requested later.
- **CLI exit-code contract** — *present.* RM-121/RM-122/RM-205/RM-215 CLI
  contract suites assert the exit-0/1/2 usage contract (`oci_cli`,
  `package_cli`), run in the `test` job.
- **Support matrix checked** — *present and intentionally evolving.*
  `docs/support-matrix.md` is generated solely from the typed
  `CAPABILITY_LEDGER`; `just capability-docs` rejects stale output in the
  required crate/package/policy job. Changing the ledger is allowed before an
  API freeze, but prose and CLI output cannot independently claim a capability.

Verdict: **in scope portions present** — CLI exit codes and the generated
support matrix are checked; Rust SemVer freeze and a C ABI are intentionally
not completion criteria.

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
  `sevenz-rust2`; PPMd7 now has bounded read support and independent
  `sevenz-rust2` producer/consumer coverage. BCJ2 now has bounded shared-seek
  streaming, independent `compcol` split/oracle evidence, and
  `sevenz-rust2` container-consumer coverage (ADR-0012). Deflate64 has
  one committed official 7-Zip producer but still lacks the Windows Explorer
  artifact required by ADR-0013. UDF has deterministic first-party conformance
  images and one committed `mkudffs` 2.3 Sparable image, but still lacks two
  further independently verified producers; xorriso is explicitly ineligible
  because it does not produce UDF. Not
  universal across every format/method. Verdict: **partial**.

### 6. Malformed, fuzz, resource-arithmetic, symlink-race, and decompression-bomb gates pass — **present**

- `fuzz` job (nightly, cargo-fuzz): panic-abort regression replay + bounded
  campaign over the committed corpus on portable and native, with
  `RUSTFLAGS: -C overflow-checks=yes` keeping malformed length **arithmetic**
  fail-closed (`xtask fuzz-ci`).
- Decompression bombs bounded by `Limits::decoded_total` throughout (ZIP/7z/CAB/
  XAR/UDF/OCI/package suites; e.g. `*_bomb_is_bounded_by_limits`,
  `decompression_bomb_is_bounded`). Symlink-race / traversal / symlink-escape
  covered by the capability filesystem (ADR-0007) and RM-202 apply tests
  (`plan_rejects_entries_escaping_through_a_layer_symlink`,
  `plan_rejects_traversal_and_duplicate_paths`). Malformed/truncated inputs
  return structured errors across all provider suites. Verdict: **present**.

### 7. 10 GiB streaming soak stays within the documented RSS budget — **present**

- `large_stream_v2` synthesizes logical 10 GiB tar, gzip, xz, and zstd inputs
  without materializing archive-sized fixtures, consumes every byte through
  `ArchiveReader`, and asserts Linux `VmHWM <= 128 MiB`.
- `just streaming-soak` runs each codec in a separate release-test process.
  The required `streaming-soak` CI job runs that recipe and is a dependency of
  `ci-required`. Verdict: **present**.

### 8. Native and portable performance gates pass without unapproved sustained regressions — **partial**

- Baseline performance / RSS data is collected in the Campaign 1 completion
  evidence (referenced from `docs/tracking/README.md`). However, **no automated
  performance-regression gate is wired into `ci.yml`** — there is no benchmark
  job comparing native vs portable throughput against a baseline with an
  approval mechanism for sustained regressions. Verdict: **partial** — baseline
  data exists; the enforcing gate does not.

### 9. Portable/native, no_std, WASI inspection, big-endian, 32-bit, MSRV, and all-features CI pass — **implemented**

- Covered by CI: **portable/native** (`test` job runs both profiles across
  ubuntu/windows/macOS), **no_std** (`no_std` job, thumbv7em-none-eabi),
  **big-endian** (`big-endian` job, s390x under qemu), **MSRV** (`msrv` job,
  workspace-wide 1.88), **32-bit**
  (`check-32-bit-windows` compiles both
  maximal profiles for `i686-pc-windows-msvc`), **WASI inspection**
  (`wasi` compiles core, every portable codec, and the flagship inspection
  stack for `wasm32-wasip1`), and the maximal-features profiles inside `test`.
- **DEV-124 blocker (now resolved on `main`):** DEV-78 is blockedBy DEV-124,
  which removed the flaky async/filter codec hang that intermittently timed out
  the `big-endian`, `test (macos-latest)`, and `test (ubuntu-latest)` jobs.
  DEV-124's deterministic root fix has **landed (#70)** — the worker-thread
  wakeup deadlock in `filter/xz.rs` is fixed and guarded by
  `async_xz_never_deadlocks_under_slow_source`, replacing the old
  re-run-the-job (`gh run rerun <id> --failed`) workaround. The covered axes can
  now be declared durably green *once* the acceptance's sustained ≥20 hang-free CI
  reps are recorded; that confirmation is the only remaining item for the covered
  axes. Verdict: **implemented** at the source/required-gate level; long-running
  remote durability history remains operational evidence rather than a code
  gap.

### 10. Release candidates — **excluded**

Release candidates, tags, version bumps, publishing, and compatibility freezes
are not completion gates for this continuation.

## Still-open checkboxes (remaining tasks for the gate's true state)

- **Checkbox 2** — implemented format cells now include Deflate64 read and UDF
  through the 2.50/2.60 Metadata Partition and 1.50/2.00+ Virtual/VAT
  follow-ons plus 1.50+ Sparable Partition remapping; RAR5 remains deferred by
  ADR-0013, and the overall matrix is not frozen.
- **Authenticity continuation beyond checkbox 3** — structural package
  conformance is present, but the ecosystem signature gaps enumerated in
  section 3 remain implementation work.
- **Checkbox 4** — only the CLI exit-code and generated support-matrix portions
  belong to this continuation; Rust SemVer freeze and C ABI work are explicitly
  excluded.
- **Checkbox 5** — three-producer/two-consumer completeness is not yet universal
  per format/method (ISO/cpio/7z plus Deflate64/UDF gaps noted).
- **Checkbox 8** — no CI performance-regression gate exists (only Campaign 1
  baseline data).
- **Checkbox 9** — every listed build axis now has a required CI job. Sustained
  remote-run history remains to be accumulated after merge.

## Status tally

- **Present: 4** — checkboxes 1, 3 (structural conformance only), 6, 7.
- **Partial: 5** — checkboxes 2, 4, 5, 8, 9.
- **Excluded: 1** — checkbox 10.

Ten listed checkboxes: **4 present / 5 partial / 1 excluded**. The
final gate is **not** met; no checkbox may be overridden by date or version. The
DEV-124 root fix has landed (#70), clearing checkbox 9's flaky blocker; the
covered CI axes still need the acceptance's sustained ≥20 hang-free reps recorded
before they count as durably green. This document is an audit snapshot only — it
closes nothing.
