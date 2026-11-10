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
    [--zip-compression METHOD] [--zip-encryption METHOD]
    [--7z-compression METHOD] [--7z-filter FILTER]
    [--7z-solid | --7z-non-solid] [--7z-encryption METHOD]
    [--xar-compression METHOD]
    [--password-file FILE | --password-prompt] ARCHIVE INPUT...
```

Creation formats are `tar`, `cpio`, `ar`, `zip`, `mtree`, `7z`, `iso9660`, and `xar`.
Outer filters are `none`, `gzip`, `bzip2`, `xz`, `zstd`, `lz4`, `lzop` (`lzo`), Unix `compress`, `lzip`,
LZMA-alone `lzma`, RFC 4648 `base64`, and POSIX `uuencode` (`uu`/`uue`).
Base64 and LZMA-alone are signatureless and therefore require explicit selection when reading; uuencode and lzop are detected from their headers.
Creation uses `ArchiveEngine`, `CreateOptions`, `StreamingArchiveBuilder`, and `SeekArchiveBuilder`, so the same finite limits, writer state machines, and safe archive-name policy apply to the Rust API and CLI.
Seek-native 7z, ISO 9660, and XAR creation requires a file destination and cannot use an outer filter.
`--xar-compression` accepts `store`, `zlib`, or `bzip2` and maps directly to `XarWriteOptions`; Store is the default.
Each regular-file payload is a separate compressed stream, codec memory and encoded expansion are bounded,
and the heap uses the writer's bounded spill-to-disk spool.
JSON success records report the effective `xar_compression`.

ZIP `METHOD` values are `store`, `deflate`, `bzip2`, `lzma`, `ppmd8`, `zstd`,
and `xz` for compression, and `none`, `zipcrypto`, `aes128`, `aes192`, and `aes256` for encryption.
They map directly to `ZipWriteOptions`.
An encrypted selection requires a password source; `none` rejects one.
ZIP-only options on another output format fail before the destination is opened.
JSON creation success records report the effective `zip_compression` and `zip_encryption`.

7z compression `METHOD` values are `store`, `lzma`, `lzma2`, `ppmd7`,
`deflate`, `bzip2`, and `zstd`.
`FILTER` is `none`, a `delta:1` through `delta:256` distance, or one of the implemented `bcj-x86`, `bcj-ppc`, `bcj-ia64`, `bcj-arm`, `bcj-arm-thumb`,
`bcj-arm64`, `bcj-sparc`, and `bcj-riscv` preprocessors.
The solid flags are mutually exclusive.
Encryption is `none` or `aes256`.
These map directly to `SevenZipWriteOptions`; encrypted selection requires a password source, while supplying a password without an explicit profile selects AES-256.
JSON success records report the effective `sevenz_compression`,
`sevenz_filter`, `sevenz_solid`, and `sevenz_encryption`.

Archive read commands auto-detect an RPM lead, remove the bounded signature and main headers, then continue through the ordinary nested-filter pipeline.
Thus gzip/xz/zstd/bzip2 or uncompressed cpio payloads use the same reader and extraction-policy implementation as standalone archives.
RPM writing remains unsupported.

mtree creation writes a v2 metadata manifest.
Input payloads are streamed for declared-size validation but are intentionally not embedded in the result.

Recognized filename suffixes, including `.7z`, `.iso`, and `.xar`, infer the format and outer filter; explicit flags take precedence, while standard output still requires `--format`.
Directory inputs ending in `.tar.Z`, `.tar.lzo`, `.tar.lzop`, `.tar.lz`, `.tar.lzma`,
`.tar.uu`, or `.tar.uue` infer compress, lzop, lzip, LZMA-alone, or uuencode respectively.
Directory children are emitted in archive-native byte order and duplicate archive paths are rejected.
`--reproducible` uses portable fixed modes and omits host ownership and timestamps.
JSON success output reports `metadata_profile` as `reproducible` or `filesystem`.

For a file `ARCHIVE`, creation writes to a unique `create_new` sibling,
synchronizes it, and publishes it without replacing an existing destination.
Failure before publication removes the sibling. An archive path inside a
directory input is refused to prevent the output from becoming one of its own
members.

For `ARCHIVE` equal to `-`, sequential archive bytes are the only standard output.
Streaming cannot retract bytes: if a later input fails, exit is 1 and the already-written prefix remains partial.
`--json create -` is therefore a usage error instead of mixing JSON and archive bytes.
Seek-native formats reject `-` before output.

## `oxarchive convert`

```text
oxarchive [--json] convert [--from-format FORMAT] [--format FORMAT]
    [--filter FILTER] [--reject-metadata-loss]
    [--password-file FILE | --password-prompt] SOURCE DEST
```

`SOURCE` and `DEST` must be files.
Their suffixes select the input format and the output format/filter unless an explicit option overrides inference.
The command dispatches to the matching sequential/seek `ArchiveTranscoder` method;
password input is accepted for ZIP, 7z, and sequential RAR 3.x/4.x or RAR5 sources.

Conversion writes a unique `create_new` sibling of `DEST`, synchronizes it, and publishes it without replacing an existing path.
A failed conversion or failed publication removes the sibling and leaves an existing destination untouched.
Every successful conversion reports the bounded typed metadata losses produced by the library.
`--reject-metadata-loss` fails before writing the first affected entry instead.

JSON success output has type `convert` and includes `source_format`,
`destination_format`, `filter`, `source`, `destination`, `entries`,
`payload_bytes`, `metadata_losses`, and `complete`.
Each loss carries `entry_index`, `path`, `path_raw_hex`, and the stable `field` name.

## `oxarchive edit`

```text
oxarchive [--json] edit [--from-format FORMAT] [--format FORMAT]
    [--filter FILTER] [--reject-metadata-loss]
    [--password-file FILE | --password-prompt]
    (--remove PATH | --rename FROM=TO)... SOURCE DEST
```

Edit uses the same file-only format selection, access dispatch, password rules,
metadata-loss policy, and atomic no-replace publication as `convert`.
At least one operation is required.
Paths match archive-native name bytes exactly;
command-line edit paths are UTF-8.
All operations must match an input entry.
Retained and renamed output paths are checked for traversal, host aliases,
duplicates, and topology conflicts.
Exact hardlink targets follow renames, and a removal that would leave a retained hardlink dangling fails closed.

JSON success output has type `edit` and adds `source_entries`,
`removed_entries`, and `renamed_entries` to the conversion completion fields.
No completion record or destination is published after any edit, decode,
fidelity, or publication failure.

## Split 7z, ZIP, and RAR path input

Every archive read command accepts `--discover-volumes`.
This is the only CLI operation that inspects adjacent paths.
Its filesystem operand must name numeric first-volume `bundle.7z.001`, terminal `bundle.zip` for a standard split ZIP, modern RAR `bundle.part001.rar`, or legacy RAR 3.x/4.x `bundle.rar`.
Derived names replace only that final number: `.002` and later for 7z, EOCD-declared `.z01` and later disks before the terminal ZIP,
`.part002.rar` and later for modern RAR, or `.r00` through `.r99` for legacy RAR.
Width and extension case are preserved where applicable.

Discovery is explicit, same-directory, and bounded by the library's default per-source, source-count, and aggregate encoded-byte limits.
Session opening traverses the bounded logical archive once so every required encoded volume is included in its immutable digest, then rewinds for inspect/plan/apply.
It cannot be combined with archive input `-`, an explicit format other than `7z`,
`zip`, `rar-legacy`, or `rar5`, or a caller-owned `VolumeSet`.
Missing required siblings remain typed errors.
Password sources remain available for encrypted split ZIP and 7z archives; encrypted RAR volumes remain outside the volume provider contract.

## Archive passwords

The archive read commands `list`, `extract`, `inspect`, `plan`, `apply`, and
`verify`, plus ZIP and 7z `create`, accept at most one of:

```text
--password-file FILE
--password-prompt
```

Read passwords are consumed by ZIP, 7z, or sequential RAR 3.x/4.x sessions,
selected automatically or explicitly with `--format zip`, `--format 7z`, or `--format rar-legacy`.
Supplying one for another format is an error rather than an ignored option.
Explicit read selection accepts `raw`, `tar`, `cpio`, `ar`,
`zip`, `7z`, `iso` (alias `iso9660`), `udf`, `cab`, `xar`, `lha` (alias `lzh`),
`warc`, `mtree`, `rar-legacy` (alias `rar4`), `rar5`, and `empty`.
Prepared engine sessions and the CLI spool their input before dispatching formats which require seeking.
Both explicit RAR selections enable a bounded SFX scan; the signature must begin within the first 1 MiB.
The RAR 3.x/4.x path accepts Store files and directories, validates header/data CRC32 and resource limits, decodes extended mtime/ctime/atime,
preflights stored Unix symlink targets, streams and reports checksum-verified auxiliary/recovery blocks without repairing them, and header-verifies then skips NEWSUB payloads.
Raw main/file flags, encryption version, host OS, and file attributes are retained in namespaced metadata.
Ordinary input without `--discover-volumes` still rejects volume and split flags; the CLI path option and library's caller-owned `VolumeSet` sequence physical volumes and join split Store or non-solid RAR3 LZ file parts after non-final packed CRC32 (when present), final logical CRC32, stable continuation metadata, declared-size,
ENDARC/FIRSTVOLUME, and archive-wide budget validation.
Compressed joins retain the whole packed payload only within explicit in-flight and codec-memory budgets.
Ordinary sequential input continues RAR3 LZ solid members through one bounded concrete decoder while resetting per-member extents and checksums.
Split non-file entries, PPMd/RarVM in split-volume joins, and solid split-volume compression are typed unsupported.
With `aes`, ordinary single-volume reads decrypt RAR3 AES-128-CBC headers and non-solid/non-split Store/LZ/PPMd file data through at most 16 ordered password candidates.
The implementation preserves raw archive metadata, validates optional 8-byte file salts and mandatory encrypted-header salts, bounds ciphertext/candidate/output workspace, caches zeroizing keys per salt, and releases no data until exact size and CRC32 validation.
Encrypted solid/split members and symlinks remain typed unsupported.
Without `aes` or a password source, encrypted metadata is reported before payload/header access returns typed unsupported.
The RAR5 path accepts unencrypted Store entries, verifies CRC32 or BLAKE2sp payloads, types archive comments/names/creation times/locators plus file times, Unix ownership,
versions, symlinks, and hardlinks, and preserves bounded raw extras and NTFS ACLs.
It checksum-verifies or explicitly marks skipped quick-open/recovery records and alternate streams while reporting their bounded metadata; sequential generation-0 compressed service payloads use the same static codec provider and decoded-byte budgets without appearing as entry data.
Repair is not provided.
File-encryption records expose encrypted entry metadata before payload access stops; header-encryption headers expose raw archive metadata before encrypted-header access stops.
Their framing is validated, but no decryption is claimed.
Ordinary CLI/single-source input still rejects multi-volume archives; `--discover-volumes` and the library's caller-owned `VolumeSet` can sequence physical RAR5 volumes containing complete entries and join split Store or generation-0 compressed file parts, including solid continuations, after per-part packed and final logical CRC32/BLAKE2sp plus continuation metadata, declared-size, and archive-wide budget validation.
Solid or split service payloads and all RAR5 decryption remain typed unsupported errors.
Seek-native LHA/LZH inputs whose first two bytes are `MZ` are scanned with a fixed 4 KiB window for a header beginning within the first 20 KiB.
The exact prefix length is reported as `lha/sfx-prefix-bytes` metadata.
Explicit LHA conversion selection fails with a typed limit error when that bound is exhausted; no unbounded executable scan or adjacent-file discovery occurs.
Password-protected ZIP creation defaults to WinZip AES-256 AE-2 with Deflate;
password-protected 7z creation defaults to AES-256 with solid LZMA2.
The ZIP profile flags select every implemented compression method plus AES-128/192/256 or legacy ZipCrypto.
The 7z profile flags select every implemented coder, Delta/BCJ preprocessor, solid grouping, and AES-256.
Another create format or an outer filter is rejected before output is opened.

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
oxarchive package validate PACKAGE --type <deb|rpm|alpine-apk|jar|nuget|wheel|epub|android-apk|ipa|msix> [--rpm-openpgp-key-file PATH] [--idsig-file PATH] [TRUST FLAGS]
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
canonical signer identity (CMS certificate DER, Alpine PKCS#1 public-key DER,
or the native RPM `OpenPGP` primary-key fingerprint)
and may be repeated; its equals form is accepted.
`--alpine-rsa-key-file PATH` supplies a PEM/DER RSA verification key and may be
repeated only with `--type alpine-apk`; its equals form is accepted. The file
basename must exactly match the `.SIGN.*` key ID and each key file is bounded
to 64 KiB. Duplicate key IDs, malformed keys, oversized files, or use with
another profile are usage errors. A supplied key enables validity checking but
does not grant issuer trust.
`--rpm-openpgp-key-file PATH` supplies one binary or ASCII-armored transferable
`OpenPGP` public-key certificate and may be repeated only with `--type rpm`;
its equals form is accepted. Each input is bounded to 256 KiB, must contain
exactly one certificate with valid identity and subkey bindings, and duplicates
are rejected by native primary-key fingerprint. A supplied certificate enables
validity checking but does not grant trust or trigger key discovery.
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
   RPM v4 `DSAHEADER`/`RSAHEADER`, RPM 6 `OPENPGPHEADER`, and legacy v3/v4
   `PGP`/`GPG` packets are verified against explicitly supplied certificates.
   Header signatures cover the exact serialized main header; legacy signatures
   additionally cover the streamed compressed payload. Primary keys and signing
   subkeys are considered, every applicable signature must verify, and a missing
   key remains `not-evaluated`. Malformed packets, mismatches, unsupported
   algorithms, and resource limits retain distinct typed findings.
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
   algorithms are explicit `unsupported` verdicts. Binary
   `AndroidManifest.xml` is decoded under the shared limits and reported
   independently with effective numeric SDK declarations. A separate platform
   compatibility verdict checks verified-scheme coverage for pre-24 and API
   24-27 minimum SDKs plus the target-SDK-30 v2+ rule; other platform policy and
   complete installability across an Android SDK range are not claimed.
   When `--idsig-file` is present, the bounded v4 verifier checks every
   sidecar `SigningInfo` signature and certificate/SPKI, binds the primary
   signer and preferred authenticated digest to verified v3 (or v2), binds a
   v4.1 additional block to the exact v3.1 signer, and recomputes the
   SHA-256 fs-verity-compatible Merkle root and optional serialized tree over
   every raw APK byte. Base-APK rotation evidence remains in the independent
   `android_apk_rotation` object.
   For IPA, `integrity` and `signature_validity` verify the top-level app's
   thin/universal Mach-O `CodeDirectory` page hashes, sealed special slots,
   exact `CodeResources` SHA-1/SHA-256 ordinary-resource coverage, every CMS
   signer, and signed hash-agility v1/v2 bindings for alternative code
   directories. Executable bytes are streamed outside the metadata budget;
   sparse headers and embedded signatures remain bounded. Nested-code and
   symlink resource rules are explicit `unsupported` results. A valid but
   unpinned signer has `trust: "invalid"`.
   For MSIX/APPX, `integrity` verifies the bounded `AppxBlockMap.xml` file set,
   declared uncompressed/local-header/compressed-block sizes, and SHA-256 over
   exact streamed 64-KiB uncompressed blocks. When `AppxSignature.p7x` is
   present, `signature_validity` also verifies its `PKCX`/Authenticode CMS,
   signer certificate, strict SHA-256 APPX digest header, AXPC raw file records,
   canonical pre-signature AXCD classic/ZIP64 directory, and AXCT/AXBM/optional
   AXCI footprint hashes. An unsigned package reports `not-present`; a valid but
   unpinned signer has `trust: "invalid"`. The encrypted/delta 2015 and 2017
   BlockMap vocabularies report `integrity: "unsupported"`.
6. `signer_fingerprints_sha256` is an array of lowercase SHA-256 hex strings
   for certificate DER, canonical Alpine PKCS#1 public-key DER, or the native
   RPM `OpenPGP` primary-key fingerprint whose
   signatures were cryptographically verified. An entry identifies a signer
   but does not imply trust.
7. `findings` is an array of the shared typed findings, each carrying
   `severity` (`info`/`warning`/`error`, the stable `Severity` label), `code`
   (the stable `PackageFindingCode` identifier such as `missing-debian-binary`
   or `missing-required-member`), `path` (the archive-native member or entry
   name, lossily decoded, or `null`), `path_raw_hex` (the same bytes as hex, or
   `null`), and `detail` (human context). Severity and code are read from the
   finding accessors and are never re-derived by the CLI.
8. `android_apk_manifest` is `null` for non-Android profiles. Android APK
   reports carry `validity`, effective numeric `minimum_sdk` and `target_sdk`
   (or `null` unless parsing verified), and manifest-specific typed `findings`.
   Numeric declarations include Android's API-1 defaults. Unmapped development
   codenames report `unsupported` instead of being guessed.
9. `android_apk_compatibility` is `null` for non-Android profiles. Android APK
   reports carry `validity`, the effective `minimum_sdk` and `target_sdk`, and
   typed `findings`. It checks pre-24 v1 coverage, API 24-27 v1/v2 coverage, and
   the target-SDK-30 v2-or-newer rule independently of cryptographic signature
   validity and issuer trust.
10. `android_apk_rotation` is `null` unless authenticated v3/v3.1 rotation
   evidence is present. Its object carries `v3_1_present`, `rotation_min_sdk`,
   `targets_dev_release`, and ordered `signers` and `lineage` arrays. A signer
   records its scheme, minimum/maximum SDK, active certificate fingerprint,
   lineage depth, and development marker. A lineage level records its
   certificate fingerprint, flags, signed algorithm, and next algorithm in
   numeric and zero-padded hexadecimal forms. These fields are authenticated
   evidence, not issuer-trust decisions.
11. `android_apk_v4` is `null` for non-Android profiles. Android APK reports
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
`profile_valid` is true and integrity, signature validity, trust, and Android
platform compatibility (when present) are not `invalid`; it is 1 when the
profile was not satisfied, one of those evaluated dimensions is invalid, or a
runtime error occurred, and 2 for a usage failure. `not-present`,
`not-evaluated`, and `unsupported` remain explicit non-success verdicts but do
not by themselves change the process exit status.

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
