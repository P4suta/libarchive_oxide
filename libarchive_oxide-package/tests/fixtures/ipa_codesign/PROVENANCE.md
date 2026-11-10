<!--
SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
SPDX-FileCopyrightText: Gregory Szorc and apple-platform-rs contributors

SPDX-License-Identifier: MPL-2.0 AND (MIT OR Apache-2.0)
-->

# rcodesign IPA fixture provenance

The two packages contain a repository-owned minimal test bundle signed offline with `rcodesign` 0.29.0 from [`indygreg/apple-platform-rs`](https://github.com/indygreg/apple-platform-rs),
whose code and test identities are MPL-2.0.
The signing identity is the upstream `apple-codesign/src/testdata/self-signed-rsa-apple-development.pem` test key and certificate.
Only its public certificate is embedded in these IPA files; no private key is committed here.

The rcodesign Windows release archive was verified before use with SHA-256 `54bb500e2da7a8de02fcae0f331d1cac6e6d7173b4281042ff9c528ba3159aaa`.
Signing used the fixed time `2023-11-05T10:00:00Z`, disabled timestamp-network access with `--timestamp-url none`, and explicitly supplied the bundle's `Info.plist` and generated `_CodeSignature/CodeResources` envelope.

- `rcodesign-signed.ipa` uses one SHA-256 `CodeDirectory`.
- `rcodesign-dual-digest.ipa` re-signs the same Mach-O with SHA-1 primary and SHA-256 alternative directories, producing both Apple hash-agility signed attributes (`1.2.840.113635.100.9.1` and `.9.2`).

Both executables report a valid CMS signature under `rcodesign print-signature-info`; `rcodesign verify` reports no detected problems.
The repository additionally verifies page hashes, special slots, resource seals,
CMS, hash agility, and explicit trust separation independently.

SHA-256:

- `53b151628ae007db595e71de9083957b4027d73c9614c689d735f152fbb2ae59` `rcodesign-signed.ipa`
- `d853fdeadebec62a9b16313a1adf35b1b8917a36e0d0b71b9d85997aa02618bd` `rcodesign-dual-digest.ipa`
