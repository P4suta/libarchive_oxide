# CLI and streaming-output contract

`oxarchive` is the single command-line entry point and follows this process
contract:

| Exit | Meaning | Standard output | Standard error |
|---:|---|---|---|
| 0 | operation completed | requested data or report | verbose diagnostics only |
| 1 | operational failure | may contain an explicitly documented partial stream | error diagnostic |
| 2 | usage or unsupported option | empty | usage diagnostic |

Help and version output use standard output and exit 0. Unsupported options are
never silently ignored.

## `oxarchive create`

```text
oxarchive [--json] create [--format FORMAT] [--filter FILTER] [--reproducible]
    [--password-file FILE | --password-prompt] ARCHIVE INPUT...
```

Sequential formats are `tar`, `cpio`, `ar`, and `zip`. Outer filters are
`none`, `gzip`, `bzip2`, `xz`, `zstd`, and `lz4`. Creation uses
`ArchiveEngine`, `CreateOptions`, and `StreamingArchiveBuilder`, so the same
finite limits, writer state machines, and safe archive-name policy apply to the
Rust API and CLI.

Recognized filename suffixes infer the format and outer filter; explicit flags
take precedence, while standard output still requires `--format`. Directory
children are emitted in archive-native byte order and duplicate archive paths
are rejected. `--reproducible` uses portable fixed modes and omits host
ownership and timestamps. JSON success output reports `metadata_profile` as
`reproducible` or `filesystem`.

For a file `ARCHIVE`, creation writes to a unique `create_new` sibling,
synchronizes it, and publishes it without replacing an existing destination.
Failure before publication removes the sibling. An archive path inside a
directory input is refused to prevent the output from becoming one of its own
members.

For `ARCHIVE` equal to `-`, archive bytes are the only standard output.
Streaming cannot retract bytes: if a later input fails, exit is 1 and the
already-written prefix remains partial. `--json create -` is therefore a usage
error instead of mixing JSON and archive bytes.

## Archive passwords

The archive read commands `list`, `extract`, `inspect`, `plan`, `apply`, and
`verify`, plus ZIP `create`, accept at most one of:

```text
--password-file FILE
--password-prompt
```

Read passwords are consumed only by automatically detected seek-native ZIP or
7z sessions. Supplying one for a sequential format, another seek format, or an
explicit sequential `--format` is an error rather than an ignored option.
Password-protected creation is WinZip AES-256 AE-2 ZIP with Deflate; another
create format or an outer filter is rejected before output is opened.

`FILE` must name a regular file, not a directory, symlink, device, pipe, or
standard input. It must be non-empty after removal of one trailing LF or CRLF
and at most 64 KiB. On Unix, every group and other permission bit must be clear
(mode `0600` or stricter); the opened file identity and permissions are checked
again to detect replacement while opening. `--password-file -` is always a
usage error.

`--password-prompt` reads without echo through the maintained `rpassword`
console adapter. It requires an interactive TTY and is refused when archive
input is `-`, so archive bytes and a secret never compete for standard input.
The returned allocation is moved directly into `SecretBytes`, which zeroizes
it on drop. Prepared ZIP/7z sessions retain only that redacted, zeroizing value
so `inspect`, `plan`, and `apply` rewinds keep authentication enabled.

Literal password argv forms are never supported. `--password`,
`--password=VALUE`, `-P`, and `-PVALUE` are detected before command dispatch or
file I/O and return exit 2 with a fixed diagnostic that does not echo the
argument. JSON output, human output, errors, and debug formatting never expose
the secret.

## Bounded inspection records

`oxarchive --json inspect ARCHIVE` is JSON Lines. Each line is a complete JSON
value and carries `schema_version: "oxarchive.output.v0alpha1"`.

1. `inspect_start` identifies the encoded-input digest.
2. Zero or more `inspect_entry` records carry one entry at a time.
3. `inspect_complete` carries the detected format, digest, entry count, and
   `complete: true`.

The implementation writes directly from `ReaderEvent` and does not retain the
entry list. Each record is flushed before the next event. A parser or output
failure returns exit 1; records already written remain valid, and the absence
of `inspect_complete` marks the stream incomplete.

Human inspection follows the same start/entry/complete sequence. `plan`,
`apply`, and `verify` remain complete reports. `apply` JSON also exposes all
filesystem capability findings instead of discarding unsupported, refused,
partial, or OS-error metadata outcomes.

## `oxarchive oci`

```text
oxarchive oci inspect LAYER
oxarchive oci verify LAYER --digest sha256:... --diff-id sha256:...
oxarchive oci apply [POLICY FLAGS] LAYER DEST --digest sha256:... --diff-id sha256:...
```

The `oci` subcommands read OCI image layers (tar, tar+gzip, tar+zstd) through
the layer engine, plan, and report types of `libarchive_oxide::oci`
(`OciLayerEngine`, `OciLayerApplier`, `LayerDigests`, `OciApplyReport`). The CLI
re-implements no OCI whiteout, opaque-directory, digest, ownership, or path
policy; it only renders the shared types. Every `oci` subcommand emits machine
JSON regardless of the top-level `--json` flag, and every record carries
`schema_version: "oxarchive.output.v0alpha1"`. A layer is named by two SHA-256
values: the compressed `digest` over the stored blob and the `diff_id` over the
decoded tar stream, both rendered as `sha256:<64 hex>` descriptors.

`oci inspect LAYER` is JSON Lines and streams one entry at a time, mirroring the
bounded `inspect` contract:

1. `oci_inspect_start` opens the stream.
2. Zero or more `oci_inspect_entry` records carry one entry each with `index`,
   `path`, `path_raw_hex`, `kind`, `size`, `link_target`, `link_target_raw_hex`,
   `mode`, `uid`, and `gid`.
3. `oci_inspect_complete` carries `entry_count`, the compressed `digest`, the
   `diff_id`, and `complete: true`.

Each record is flushed before the next entry, and the entry list is never
retained. A read or parse failure returns exit 1; the absence of
`oci_inspect_complete` marks the stream incomplete. `LAYER` may be `-` for
standard input.

`oci verify LAYER --digest ... --diff-id ...` emits one `oci_verify` object.
Both digest flags are required; a missing or malformed `sha256:<hex>` argument
is a usage error (exit 2). A match reports `verified: true` with the computed
`digest` and `diff_id` and exits 0. A mismatch reports `verified: false` and a
`mismatch` object (`kind`, `expected`, `computed`) and exits 1. `LAYER` may be
`-`.

`oci apply [POLICY FLAGS] LAYER DEST --digest ... --diff-id ...` emits one
`oci_apply` object. It plans and applies through `OciLayerApplier`, which
verifies both digests before touching `DEST`, so a mismatch reports
`applied: false` with a `mismatch` object, leaves the destination unchanged, and
exits 1. A successful apply reports `applied: true`, the verified `digest` and
`diff_id`, the `materialized`, `removed`, `cleared`, and `rejected` counts, and
a `findings` array of filesystem capability findings. Policy flags are
`--overwrite`, `--allow-symlinks`, `--allow-hardlinks`, and
`--allow-special-files`; a policy refusal keeps the entry visible in the report
and returns exit 1. `oci apply` requires a seekable `LAYER` file so it can rewind
between the verify and apply passes; `-` is a usage error (exit 2).

## `oxarchive package`

```text
oxarchive package validate PACKAGE --type <deb|rpm|alpine-apk|jar|nuget|wheel|epub|android-apk|ipa|msix> [--idsig-file PATH] [TRUST FLAGS]
```

The `package validate` subcommand drives `PackageVerifier` from the dedicated
`libarchive_oxide-package` crate. The CLI re-implements no package-structure
interpretation or finding classification; it selects a profile, opens a bounded
input, and renders the shared typed verdicts and findings. The verifier performs
no implicit network access. Every invocation emits machine JSON regardless of
the top-level `--json` flag, and the record carries
`schema_version: "oxarchive.output.v0alpha1"`.

`--type` is required and selects the profile: `deb`, `rpm`, `alpine-apk`,
`jar`, `nuget`, `wheel`, `epub`, `android-apk`, `ipa`, or `msix`. The ambiguous
name `apk` is rejected. The equals form `--type=jar` is accepted; a repeated
`--type` is a usage error. A missing or unknown type, an unknown or missing
subcommand, or more than one `PACKAGE` operand is a usage error (exit 2).
`--trusted-signer-sha256 HEX` adds one exact, 64-hex-digit SHA-256 pin of a
canonical signer identity (CMS certificate DER or Alpine PKCS#1 public-key DER)
and may be repeated; its equals form is accepted.
`--alpine-rsa-key-file PATH` supplies a PEM/DER RSA verification key and may be
repeated only with `--type alpine-apk`; its equals form is accepted. The file
basename must exactly match the `.SIGN.*` key ID and each key file is bounded
to 64 KiB. Duplicate key IDs, malformed keys, oversized files, or use with
another profile are usage errors. A supplied key enables validity checking but
does not grant issuer trust.
`--idsig-file PATH` supplies an Android APK Signature Scheme v4/v4.1 detached
sidecar and is valid only with `--type android-apk`. Its equals form is
accepted. It may appear once, must name a file rather than `-`, and is never
derived from the APK path. Omitting it is valid and produces an explicit
sidecar-specific `not-evaluated` result; the CLI neither probes a sibling path
nor performs network access.
`--allow-unsigned` explicitly allows a package proven to be unsigned to satisfy
trust policy. A malformed pin or repeated `--allow-unsigned` is a usage error.
Neither option enables network access.

`package validate` emits one `package_validation` object:

1. `schema_version` and `type: "package_validation"`.
2. `profile` echoes the stable lowercase `--type` label.
3. `container_readable` (bool) reports whether the outer container structure was
   parseable at all.
4. `profile_valid` (bool) reports whether the package additionally satisfied its
   profile with no blocking findings. The two verdicts are independent: a
   readable container can still fail its profile.
5. `integrity`, `signature_validity`, and `trust` are independent verdicts:
   `verified`, `invalid`, `not-present`, `not-evaluated`, or `unsupported`.
   A detected signature container is only `not-evaluated` until its signed
   bytes and algorithm have actually been checked; structure validity never
   implies signature validity or issuer trust. JAR and Android APK v1 are
   checked through their manifest, `.SF`, and bounded embedded CMS chain; the
   resulting signer-certificate SHA-256 fingerprints are evaluated only
   against explicit offline certificate pins. Alpine APK v2 RSA/SHA-1,
   RSA/SHA-256, and RSA/SHA-512 signatures cover the exact compressed control
   member; `.PKGINFO datahash` covers the exact compressed data member.
   Android APK v2/v3 RSA-PSS, RSA-PKCS#1, and P-256/P-384
   ECDSA-with-SHA-256 signatures cover the bounded Signing Block signed-data;
   their SHA-256/SHA-512 content digests are recomputed as streamed 1 MiB
   chunks over the APK outside the Signing Block with the required EOCD offset
   rewrite. For each signer, the AOSP platform-range policy selects the
   strongest signature at every represented algorithm-introduction SDK and all
   selected records must verify. Only content-digest kinds requested by those
   winners are integrity inputs. Standard and fs-verity SHA-256 records may
   coexist; the latter is recomputed as a bounded 4 KiB salted tree over the
   specification's virtual APK. Authenticated APK v1 anti-stripping declarations
   are enforced.
   Bounded v3 proof-of-rotation verifies every predecessor signature,
   certificate, flag, and algorithm through the active signer. v3/v3.1
   targeted signers enforce authenticated SDK ranges, release/development
   boundaries, lineage extension, and rotation-min-SDK stripping protection.
   DSA, ECDSA-with-SHA-512/P-521, out-of-backend RSA sizes, and unknown lineage
   algorithms are explicit `unsupported` verdicts. The record authenticates
   signer ranges but does not parse binary-manifest SDK declarations or claim
   installability across an Android SDK range.
   When `--idsig-file` is present, the bounded v4 verifier checks every
   sidecar `SigningInfo` signature and certificate/SPKI, binds the primary
   signer and preferred authenticated digest to verified v3 (or v2), binds a
   v4.1 additional block to the exact v3.1 signer, and recomputes the
   SHA-256 fs-verity-compatible Merkle root and optional serialized tree over
   every raw APK byte. Base-APK rotation evidence remains in the independent
   `android_apk_rotation` object.
   For MSIX/APPX, `integrity` verifies the bounded `AppxBlockMap.xml` file set,
   declared uncompressed/local-header/compressed-block sizes, and SHA-256 over
   exact streamed 64-KiB uncompressed blocks. `AppxSignature.p7x` presence
   remains `signature_validity: "not-evaluated"` until its CMS signed bytes are
   implemented; an unsigned package reports `not-present`. The encrypted/delta
   2015 and 2017 BlockMap vocabularies report `integrity: "unsupported"`.
6. `signer_fingerprints_sha256` is an array of lowercase SHA-256 hex strings
   for certificate DER or canonical Alpine PKCS#1 public-key DER whose
   signatures were cryptographically verified. An entry identifies a signer
   but does not imply trust.
7. `findings` is an array of the shared typed findings, each carrying
   `severity` (`info`/`warning`/`error`, the stable `Severity` label), `code`
   (the stable `PackageFindingCode` identifier such as `missing-debian-binary`
   or `missing-required-member`), `path` (the archive-native member or entry
   name, lossily decoded, or `null`), `path_raw_hex` (the same bytes as hex, or
   `null`), and `detail` (human context). Severity and code are read from the
   finding accessors and are never re-derived by the CLI.
8. `android_apk_rotation` is `null` unless authenticated v3/v3.1 rotation
   evidence is present. Its object carries `v3_1_present`, `rotation_min_sdk`,
   `targets_dev_release`, and ordered `signers` and `lineage` arrays. A signer
   records its scheme, minimum/maximum SDK, active certificate fingerprint,
   lineage depth, and development marker. A lineage level records its
   certificate fingerprint, flags, signed algorithm, and next algorithm in
   numeric and zero-padded hexadecimal forms. These fields are authenticated
   evidence, not issuer-trust decisions.
9. `android_apk_v4` is `null` for non-Android profiles. Android APK reports
   carry an object with `revision` (`"v4.0"`, `"v4.1"`, or `null`),
   sidecar-specific `integrity`, `signature_validity`, and `trust`,
   `signer_fingerprints_sha256`, and `findings`. The nested dimensions remain
   independent: for example, a correctly signed sidecar whose serialized
   Merkle tree was altered reports verified signature validity and invalid
   integrity. Missing optional input uses `revision: null` and
   `not-evaluated` dimensions with `signature-sidecar-not-provided`; it is not
   inferred as success.

The record is written before any exit-code error, so a machine consumer always
observes the findings even when validation failed. Exit is 0 when
`profile_valid` is true and none of the three verification dimensions is
`invalid`; it is 1 when the profile was not satisfied, an evaluated
cryptographic dimension is invalid, or a runtime error occurred, and 2 for a
usage failure. `not-present`, `not-evaluated`, and `unsupported` remain explicit
non-success verdicts but do not by themselves change the process exit status.

`PACKAGE` may be `-` to read standard input for the `deb`, `rpm`, and
`alpine-apk` profiles, which need only sequential reads. Alpine APK v2 is
validated as its logical tar stream across concatenated gzip members and
requires `.PKGINFO`; signature entries are detected only when they precede
control and data entries. Verification drains and validates every gzip member,
retains the exact compressed signature/control members under the metadata
budget, and hashes the compressed data member without retaining it. The
ZIP-container profiles (`jar`, `nuget`, `wheel`,
`epub`, `android-apk`, `ipa`, `msix`) parse a central directory at the end of
the file and therefore require a seekable file; `-` is a usage error (exit 2)
for them.

## Completion and manual output

`oxarchive completion <bash|zsh|fish|powershell>` writes a shell completion
script, including the two password-source options, to standard output.
`oxarchive man` writes the roff manual source.
Neither form accepts `--json`, because its standard output is the requested
artifact rather than a JSON record.

## Standard streams and unsafe paths

- `list`, `extract`, `inspect`, `plan`, `apply`, and `verify` accept archive
  input `-`; `--password-prompt` cannot be used in that form.
- `oci inspect` and `oci verify` accept layer input `-`; `oci apply` requires a
  seekable file and rejects `-`.
- `package validate` accepts `PACKAGE` `-` for the `deb`, `rpm`, and
  `alpine-apk` profiles; the ZIP-container profiles require a seekable file and
  reject `-`.
- `create` accepts archive output `-`; inputs are filesystem paths.
- Extraction traversal, absolute, drive/UNC, link-order, and destination
  policy failures remain visible and return exit 1.
- Creation rejects parent-directory archive names and derives relative names
  without lossy Unix path conversion.

The schema identifier, record types, command grammar, exit meanings, and
stdout/stderr split are compatibility surfaces.
