# libarchive_oxide-cli

The single `oxarchive` command for safe archive, OCI-layer, and software-package workflows.

```sh
cargo install libarchive_oxide-cli --locked

oxarchive inspect artifact.tar.zst
oxarchive plan --json untrusted.zip
oxarchive extract untrusted.zip destination
oxarchive create artifact.tar.zst input/
oxarchive verify artifact.7z
oxarchive verify --password-file ./archive-password protected.7z
oxarchive create --password-prompt protected.zip input/
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

`create` infers `tar`, `cpio`, `ar`, or `zip` and an optional outer filter from
the output suffix; explicit `--format` and `--filter` override inference.
Extraction defaults to the conservative policy and requires explicit flags for
overwrite, links, or special files.

Package output separates structural conformance, integrity, cryptographic
signature validity, and issuer trust. The ambiguous `--type apk` is rejected;
`alpine-apk` and `android-apk` select different container rules. A detected
signature container is never reported as cryptographically valid until it has
actually been verified. Alpine APK v2 keys are supplied explicitly with
`--alpine-rsa-key-file`; the basename is the signature key ID, the file is
bounded to 64 KiB, and supplying it does not grant trust. Verified certificate
or canonical public-key fingerprints are emitted separately and become trusted
only through explicit `--trusted-signer-sha256` pins. The package crate and CLI
perform no implicit network access. Android APK v2/v3 RSA and supported ECDSA
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
declarations and Android SDK-range installability are not claimed. MSIX
validation verifies the bounded `AppxBlockMap.xml` file set, sizes, and
streamed SHA-256 hashes over 64-KiB blocks; encrypted/delta 2015/2017 BlockMap
vocabularies remain explicitly unsupported. It does not yet verify
`AppxSignature.p7x`, which remains `not-evaluated` rather than being inferred
valid from presence.

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
no-replace publication; `create -` writes only archive bytes and cannot be
combined with `--json`.

Only `oxarchive` is shipped. The former partial-compatibility `oxtar`,
`oxcpio`, `oxcat`, and `oxunzip` binaries are retired.

Exit codes are 0 for success, 1 for an operational or verification failure, and
2 for usage or unsupported options.

Encrypted ZIP/7z reads (`list`, `extract`, `inspect`, `plan`, `apply`, and
`verify`) and WinZip AES-256 AE-2 ZIP creation accept exactly one secret source:
`--password-file FILE` or `--password-prompt`. A password file must be a
regular, non-empty file of at most 64 KiB; on Unix it must deny every group and
other permission bit (mode `0600` or stricter). One trailing LF or CRLF is
removed. The prompt disables echo and requires an interactive TTY, so it is
refused when archive input is `-`. `--password-file -` is always refused.

Password values are never accepted in command-line arguments. The
`--password`, `--password=VALUE`, `-P`, and `-PVALUE` forms are rejected before
archive or secret-file I/O, and diagnostics and JSON never include the supplied
secret.

See the [full CLI contract](https://github.com/P4suta/libarchive_oxide/blob/main/docs/cli-contract.md).

Licensed under either MIT or Apache-2.0, at your option.
