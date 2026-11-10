# libarchive_oxide-cli

The single `oxarchive` command for safe archive, OCI-layer, and software-package workflows.

```sh
cargo install libarchive_oxide-cli --locked

oxarchive inspect artifact.tar.zst
oxarchive inspect --format rar-legacy legacy-sfx.exe
oxarchive plan --json untrusted.zip
oxarchive extract untrusted.zip destination
oxarchive create artifact.tar.zst input/
oxarchive create artifact.xar input/
oxarchive create --xar-compression zlib compressed.xar input/
oxarchive --json convert artifact.tar.zst artifact.xar
oxarchive --json edit --rename old.txt=new.txt --remove obsolete.txt source.zip edited.zip
oxarchive verify artifact.7z
oxarchive verify --password-file ./archive-password protected.7z
oxarchive create --zip-compression ppmd8 --zip-encryption aes192 \
  --password-prompt protected.zip input/
oxarchive create --7z-compression deflate --7z-filter delta:3 \
  --7z-non-solid --7z-encryption aes256 --password-prompt protected.7z input/
oxarchive package validate app.apk --type android-apk
oxarchive package validate app.apk --type android-apk \
  --idsig-file app.apk.idsig \
  --trusted-signer-sha256 <certificate-der-sha256>
oxarchive package validate signed.jar --type jar \
  --trusted-signer-sha256 06f73dd845505562148c9b2d658ce359a3f6e86bdc096960826ba04d0b2e4182
oxarchive package validate alpine.apk --type alpine-apk \
  --alpine-rsa-key-file alpine-devel@example.org-12345678.rsa.pub \
  --trusted-signer-sha256 <public-key-pkcs1-der-sha256>
oxarchive oci inspect layer.tar.gz
```

`create` infers `tar`, `cpio`, `ar`, `zip`, `mtree`, `7z`, `iso9660`, or `xar` and an optional outer filter from the output suffix; explicit `--format` and `--filter` override inference.
Seek-native 7z, ISO 9660, and XAR creation requires a file destination and rejects outer filters.
ZIP creation accepts `--zip-compression` with `store`, `deflate`, `bzip2`,
`lzma`, `ppmd8`, `zstd`, or `xz`, and `--zip-encryption` with `none`,
`zipcrypto`, `aes128`, `aes192`, or `aes256`.
These are thin typed `ZipWriteOptions` mappings; encrypted selections require an explicit secret source.
7z creation accepts `--7z-compression` with `store`, `lzma`, `lzma2`,
`ppmd7`, `deflate`, `bzip2`, or `zstd`; every implemented Delta/BCJ preprocessor through `--7z-filter`; `--7z-solid` or `--7z-non-solid`;
and `--7z-encryption none|aes256`.
These map directly to `SevenZipWriteOptions`.
A password source selects AES-256 by default.
XAR creation accepts `--xar-compression store|zlib|bzip2`, mapped directly to `XarWriteOptions`; Store remains the default.
`convert SOURCE DEST` requires file operands, infers both formats from suffixes,
and atomically publishes `DEST` without replacing an existing path.
Use `--from-format`, `--format`, and `--filter` to override inference.
The command selects the library transcoder's sequential/seek method from the two format capabilities, emits every typed metadata loss, and supports fail-closed `--reject-metadata-loss`.
`edit SOURCE DEST` adds one or more exact-path `--remove PATH` or `--rename FROM=TO` operations to the same access-aware rewrite.
Retained and renamed paths are validated against traversal, host aliases, duplicates, and file/directory topology conflicts.
Every operation must match; hardlink targets follow renames and removals that would leave a dangling hardlink fail closed.
The destination is published atomically without replacing an existing path.
`uuencode`/`uu`/`uue`, `base64`/`b64`, and `lzma` are available as outer filters.
Uuencode is detected from its `begin` header and inferred from `.tar.uu`/`.tar.uue`; Base64 and LZMA-alone lack reliable signatures and are selected explicitly when reading.
mtree output is a metadata manifest: input bytes are size-checked while streaming creation, but are not embedded in the manifest.
Extraction defaults to the conservative policy and requires explicit flags for overwrite, links, or special files.

Package output separates structural conformance, integrity, cryptographic
signature validity, and issuer trust. The ambiguous `--type apk` is rejected;
`alpine-apk` and `android-apk` select different container rules. A detected
signature container is never reported as cryptographically valid until it has
actually been verified. Alpine APK v2 keys are supplied explicitly with
`--alpine-rsa-key-file`; the basename is the signature key ID, the file is
bounded to 64 KiB, and supplying it does not grant trust. Verified certificate
or canonical public-key fingerprints are emitted separately and become trusted
only through explicit `--trusted-signer-sha256` pins. The package crate and CLI
perform no implicit network access. RPM transferable `OpenPGP` public-key
certificates are supplied explicitly with repeatable
`--rpm-openpgp-key-file`; each input is bounded to 256 KiB. The CLI verifies
v4 header signatures, RPM 6 `OPENPGPHEADER`, and legacy header-plus-payload
signatures, while trust still requires a pin of the reported SHA-256 signer
identity. Android APK v2/v3 RSA and supported ECDSA
signatures plus chunked and fs-verity content digests are verified directly
from the seekable APK, and authenticated v1 anti-stripping metadata is
enforced. Verified v3 proof-of-rotation and v3.1 targeted signer ranges are
emitted separately in `android_apk_rotation`, including lineage fingerprints,
flags, algorithms, SDK boundaries, and development markers; these fields never
grant trust. An APK v4/v4.1 `.idsig` is accepted only through the explicit
`--idsig-file PATH` option: the CLI never guesses a sibling file. Its bounded
signatures, v2/v3/v3.1 identity-and-digest bindings, SHA-256 Merkle root/tree,
signer pins, and typed findings are emitted in the nested `android_apk_v4` JSON
object. An omitted sidecar remains `not-evaluated`. Binary-manifest SDK
declarations are decoded into `android_apk_manifest`; the independent
`android_apk_compatibility` object checks verified signing-scheme coverage for
pre-24 and API 24-27 minimum SDKs plus the target-SDK-30 v2+ rule. An invalid
compatibility verdict makes validation exit 1 without collapsing signature
validity or trust. Other platform policy and complete cross-SDK installability
are not claimed. IPA validation verifies streamed Mach-O `CodeDirectory` page
hashes, special slots, the `CodeResources` file envelope, every CMS signer, and
alternative-CodeDirectory hash-agility attributes. A valid IPA signer remains
untrusted until `--trusted-signer-sha256` pins its certificate fingerprint. MSIX
validation verifies the bounded `AppxBlockMap.xml` file set, sizes, and
streamed SHA-256 hashes over 64-KiB blocks; encrypted/delta 2015/2017 BlockMap
vocabularies remain explicitly unsupported. A present `AppxSignature.p7x` is
verified through its PKCX/Authenticode CMS signer, APPX AXPC/AXCD package views,
and AXCT/AXBM/optional AXCI footprint hashes. Validity does not grant trust;
`--trusted-signer-sha256` must pin the reported certificate fingerprint.

Generate integration assets directly:

```sh
oxarchive completion bash
oxarchive completion zsh
oxarchive completion fish
oxarchive completion powershell
oxarchive man > oxarchive.1
```

Machine output uses schema `oxarchive.output.v0alpha1`. Inspection is bounded
JSON Lines with an explicit completion record. File creation uses atomic
no-replace publication; conversion uses the same commit path. `create -` writes
only archive bytes and cannot be combined with `--json`.

Only `oxarchive` is shipped. The former partial-compatibility `oxtar`,
`oxcpio`, `oxcat`, and `oxunzip` binaries are retired.

Exit codes are 0 for success, 1 for an operational or verification failure, and
2 for usage or unsupported options.

Encrypted ZIP, 7z, RAR 3.x/4.x, and RAR5 reads (`list`, `extract`, `inspect`,
`plan`, `apply`, and `verify`) plus WinZip AES-128/192/256 AE-2, legacy ZipCrypto, and 7z AES-256 creation accept exactly one secret source:
`--password-file FILE` or `--password-prompt`.
A password file must be a regular, non-empty file of at most 64 KiB; on Unix it must deny every group and other permission bit (mode `0600` or stricter).
One trailing LF or CRLF is removed.
The prompt disables echo and requires an interactive TTY, so it is refused when archive input is `-`.
`--password-file -` is always refused.

Password values are never accepted in command-line arguments. The
`--password`, `--password=VALUE`, `-P`, and `-PVALUE` forms are rejected before
archive or secret-file I/O, and diagnostics and JSON never include the supplied
secret.

Split 7z input is available to every archive read command through the explicit `--discover-volumes` flag.
The archive operand must be the first numeric sibling (for example `bundle.7z.001`); `oxarchive` then opens `.002`, `.003`, and later same-directory siblings lazily under the library's finite source-count and byte limits.
Discovery is never implicit, does not search directories, and is refused for archive input `-`.
Password sources compose with this path for encrypted split 7z archives.

See the [full CLI contract](https://github.com/P4suta/libarchive_oxide/blob/main/docs/cli-contract.md).

Licensed under either MIT or Apache-2.0, at your option.
