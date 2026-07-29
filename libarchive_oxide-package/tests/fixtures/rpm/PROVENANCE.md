<!--
SPDX-FileCopyrightText: 2026 libarchive_oxide contributors

SPDX-License-Identifier: MIT OR Apache-2.0
-->

# RPM fixture provenance

This directory contains one committed, deterministic RPM artifact produced by
an implementation independent of `libarchive_oxide`:
`rpm-4.14.2.1-minimal.rpm.gz.b64`. It is wrapped with deterministic
`gzip -n -9` and base64 encoded so the byte-exact binary can be reviewed and
added with text-oriented repository tooling; the test decodes and decompresses
it in memory.

## Producer registry

| File | Producer | Container image | Payload | Integrity tags |
|------|----------|-----------------|---------|----------------|
| `rpm-4.14.2.1-minimal.rpm.gz.b64` | Fedora `rpmbuild` 4.14.2.1-5.fc30 | `fedora@sha256:3a0c8c86d8ac2d1bbcfd08d40d3b757337f7916fb14f40efcb1d1137a4edef45` | RPM v4, cpio + gzip level 9 | `PAYLOADDIGEST`/tag 5092 (compressed SHA-256) and `PAYLOADDIGESTALGO`/tag 5093 (`8`, SHA-256) |

RPM 4.14 is deliberate: it introduced the compressed payload digest while
predating RPM 4.16's uncompressed `ALT` digest. This therefore supplies a
positive independent-producer check for the compressed SHA-256 and obsolete
algorithm-id path without claiming support for compressed `ALT` hashing.
SHA-512 and SHA3-256 payload tags first appear in RPM 6; RPM 6 also changes its
payload to stripped cpio, which the current archive reader does not yet accept,
so no misleading positive RPM 6 fixture is registered here.

## Artifact identity

- Decoded size: 6,663 bytes.
- SHA-256 of the decoded RPM:
  `3784a330734498a37479a57debc86722b73ed50ccc6b7202bfa078aa8d345b82`.
- Header-declared compressed payload SHA-256:
  `f771cd9966680d5954a7c15aeb60f8cccfe32b47baa701718f028e4d7b36c2a8`.
- Synthetic payload:
  `/usr/share/libarchive-oxide/fixture.txt`, containing the exact ASCII bytes
  `libarchive-oxide RPM interoperability fixture\n`, with mtime
  `2000-01-01T00:00:00Z`.
- Capture date: 2026-07-29.

## Regeneration

The source is `rpmbuild-minimal.spec` in this directory. On a host with Docker:

```powershell
$out = (Resolve-Path C:\tmp).Path + '\libarchive-oxide-rpm-414-build'
New-Item -ItemType Directory -Force -Path $out | Out-Null
docker run --rm `
  -v "${PWD}\libarchive_oxide-package\tests\fixtures\rpm:/src:ro" `
  -v "${out}:/build" `
  fedora@sha256:3a0c8c86d8ac2d1bbcfd08d40d3b757337f7916fb14f40efcb1d1137a4edef45 `
  bash -lc "dnf install -y rpm-build >/dev/null && env SOURCE_DATE_EPOCH=946684800 rpmbuild -bb /src/rpmbuild-minimal.spec --define '_topdir /build' --define '_binary_payload w9.gzdio' --define '_buildhost fixture.invalid' --define 'source_date_epoch_from_changelog 1' --define 'clamp_mtime_to_source_date_epoch 1' --define 'use_source_date_epoch_as_buildtime 1'"
```

Run `gzip -n -9 -c` over
`$out\RPMS\noarch\libarchive-oxide-interop-1.0-1.noarch.rpm`, base64-encode the
result with 76 columns, and compare the decompressed RPM's SHA-256 with the
value above before replacing the fixture. The pinned Fedora image contains both
`gzip` and GNU `base64`.

## License / origin

The spec and payload are first-party synthetic content under this repository's
`MIT OR Apache-2.0` license. The committed bytes are output produced by RPM;
no Fedora/RPM executable, source, or third-party package content is
redistributed. The repository-wide `REUSE.toml` fixture override applies.
