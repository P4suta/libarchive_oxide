# ADR-0011: Interoperability-evidence harness and fixture-provenance policy

- Status: accepted
- Date: 2026-07-22
- Tracks: RM-301

## Context

A format reader or writer is only correct if it interoperates with the rest of
the ecosystem: bytes an independent tool produced must read back the same, and
bytes this crate produced must be accepted by independent tools. RM-300's
acceptance criteria state this concretely — every supported archive method must
be shown to read at least three independent producers' output and to be accepted
by at least two independent consumers — and additionally require that *fixture
provenance is recorded in ADRs*. Neither obligation had a home. Interop was
demonstrated ad hoc by a handful of one-off differential tests
(`sevenz_differential.rs`, `zip_write_differential.rs`), each wiring its own
comparison logic against one other crate, with no shared notion of what "the
same entry set" means and no policy for where test corpora come from or how their
origin is attested.

The later format slices (RM-302/303/304 for ZIP/7z, and onward to tar, cpio,
ar, ISO, CAB, XAR) will each need to reproduce the identical evidence shape:
N producers agree, M consumers accept. Rebuilding that scaffolding per slice
would be wasteful and would let the evidence drift in form from one method to the
next. What was missing was a single reusable machine that expresses the
"≥3 producers × ≥2 consumers" argument once, so a future slice supplies only its
own producer and consumer adapters, and a written policy for corpus provenance so
that the origin of every byte compared in a test is self-describing and auditable.

This decision adds no archive method and no runtime code. It defines the
methodology and the provenance policy, and proves the machinery on
already-supported methods — ZIP Store, ZIP Deflate, and 7z LZMA2.

## Decision

- **A single reusable interoperability-evidence harness.** The harness lives in
  the test tree as shared module code (`libarchive_oxide/tests/common/mod.rs`,
  included by a test binary with `mod common;`), not in `src/`. It has no runtime
  footprint, adds no dependency, adds no `unsafe`, and introduces no trait object:
  producers and consumers are carried as bare `fn` pointers in concrete case
  structs, so a new format slice adds a free function and a `&[]` array without
  editing the harness. The crate's `#![forbid(unsafe_code)]` and no-`dyn` gates are
  untouched.

- **One normalized, content-comparable entry model.** A logical entry set — the
  single source of truth for a test — is a list of `(raw path bytes, kind,
  content)` triples. Every producer encodes that identical set; every read-back is
  normalized to a canonical `EntryShape` and compared for equality of *content*
  (path, kind, and full uncompressed bytes), never for count alone. Paths are raw
  bytes end to end, so non-UTF-8 names survive losslessly and are never routed
  through `String`. Compression method is carried out of band as an optional field
  excluded from equality, so a Store producer and a Deflate producer of the same
  logical set still compare equal, while a consumer that *does* expose a codec view
  (e.g. the `zip` crate's per-entry method) can still be asserted against
  separately. A directory whose path a spec-conformant producer stores with a
  trailing slash is normalized identically to one this crate stores without it, in
  the shape's sole constructor, so that a real and benign representational
  difference does not read as disagreement.

- **The "≥3 producers agree" evidence, expressed once.** Given a logical entry set
  and an arbitrary-length slice of producer cases, the harness asserts that this
  crate reads every producer's output back into shapes identical to those *derived
  from the source-of-truth set*. Comparing against the derived truth — not merely
  cross-comparing producers — means a bug common to all producers cannot pass. Each
  producer case names itself, so any disagreement names the exact producer that
  diverged.

- **The "≥2 consumers accept" evidence, expressed once.** Given this crate's
  writer output and an arbitrary-length slice of consumer cases, the harness
  asserts that every independent consumer reconstructs the identical content. N and
  M are simply slice lengths, so a future slice passes three producers and two
  consumers per method without any change to the harness.

- **This crate itself is one valid producer and one valid consumer.** Its writer
  is a producer case and its reader is a consumer case, sitting in the same slices
  as the independent crates, so the system under test is always measured against
  independent references rather than only against itself.

### Fixture-provenance policy (RM-300 acceptance: provenance recorded in ADRs)

- **Default: deterministic in-code generation from pinned dev-dependencies.** The
  preferred corpus is generated at test run time from independent producer crates
  already pinned in `[dev-dependencies]`. This is hermetic (no network), byte-
  deterministic, and commits no binary blobs that could rot or drift from the code
  that reads them. Each producer and consumer records its identity as a
  `crate@version` label taken verbatim from the `Cargo.toml` pin (e.g. `zip@8.6.0`,
  `sevenz-rust2@0.21.3`), and that label is embedded at the call site so every
  interop assertion is self-describing: a failure names the exact producer or
  consumer, and its exact version, that disagreed. The pins are the source of
  provenance truth; bumping one is a deliberate, reviewed change that updates the
  label strings. An independent producer that is neither this crate nor a
  third-party crate — a hand-assembled byte layout written directly in the test —
  is recorded the same way, with a descriptive label and a note of the layout it
  follows, and counts as independent of both this crate and the codec crates.

- **Escape hatch: opaque real-world fixtures on disk, with recorded provenance.**
  When a future slice needs a byte-exact artifact that only an external tool can
  produce (a specific packer's output, a real-world sample), that artifact is
  committed under a format-partitioned tree,
  `libarchive_oxide/tests/fixtures/<format>/<producer>/<case>.<ext>`, and gains a
  row in that format's registry, `libarchive_oxide/tests/fixtures/<format>/PROVENANCE.md`.
  Each such row records the
  producing tool, its exact version, the exact command line used, the capture date,
  the SHA-256 of the committed file, and the upstream license and redistribution
  note; regeneration must be byte-reproducible from that record. Each format's
  `PROVENANCE.md` is the running registry of every producer and consumer backing the
  harness for that format and the documented policy for adding more — it doubles as
  the how-to-extend guide for the format slices, so no separate corpus artifact is
  created until a slice actually needs an external-tool byte stream.

- **Why this satisfies "fixture provenance recorded in ADRs".** RM-300 requires
  that the origin of test corpora be attested in the architecture record rather
  than left implicit in test code. This ADR *is* that record: it fixes the default
  (deterministic in-code generation, identity captured as `crate@version` from the
  pins) and the exception (opaque on-disk fixtures under
  `tests/fixtures/<format>/<producer>/` with a mandatory row in that format's
  `tests/fixtures/<format>/PROVENANCE.md`
  carrying tool, version, command, date, hash, and license). Because provenance
  labels are derived from the same pins the build resolves and are surfaced in
  every assertion message, the evidence is auditable from the ADR down to the exact
  bytes compared, and future slices extend the registry without re-deciding policy.

### Proven this slice

- ZIP Store and ZIP Deflate: each shown to read at least three independent
  producers (this crate's writer, the `zip` crate, and a hand-assembled raw-ZIP
  byte layout) and to be accepted by at least two independent consumers (this
  crate's reader and the `zip` crate), with the `zip` consumer's per-entry method
  asserted where it exposes one.
- 7z LZMA2: shown to read two producers (this crate's writer and `sevenz-rust2`)
  and to be accepted by two consumers (this crate's reader and `sevenz-rust2`),
  gated behind the `sevenz` feature so default builds stay green.

The entry sets exercise files, directories, and a file within a subdirectory, so
the directory-path normalization is on the proven path rather than assumed.

## Consequences

Every future format slice reproduces the same interoperability argument by writing
adapter functions and passing arrays, never by re-deriving the comparison
machinery, so the shape of the evidence is uniform across ZIP, 7z, tar, cpio, ar,
ISO, CAB, XAR and beyond. Because comparison is over full uncompressed content
against a source-of-truth entry set — not entry counts — the tests cannot pass on
a trivial equality, and a bug shared by every producer is still caught. Because
provenance is captured as `crate@version` from the resolved pins and echoed in
assertion messages, an interop failure is self-explanatory and the corpus origin
is auditable without leaving the ADR.

Keeping the default corpus in-code means the common case commits no binaries and
cannot drift from the code that reads it; the on-disk escape hatch remains
available for the cases that genuinely require an external tool, at the cost of a
mandatory, byte-reproducible `PROVENANCE.md` record. Method-specific
interoperability scope for the remaining families is added by the owning slices as
they land; the RAR5 and UDF specifics in particular will be appended to this ADR
by RM-306.
