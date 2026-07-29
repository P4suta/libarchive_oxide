<!--
SPDX-FileCopyrightText: 2026 libarchive_oxide contributors

SPDX-License-Identifier: MIT OR Apache-2.0
-->

# lzip fixture provenance

`bsdtar-3.8.4-seed.tar.lz.hex` is the exact ASCII-hex encoding of a
137-byte lzip-compressed ustar archive. It was captured on 2026-07-29 from the
independent system producer:

- executable: `C:\Windows\System32\tar.exe`;
- reported producer: bsdtar 3.8.4 / libarchive 3.8.4;
- linked compression implementation: liblzma 5.8.1;
- lzip header: `LZIP 01 17` (version 1, 8 MiB dictionary);
- SHA-256:
  `1F27F1C23757ADBAE2C2F0E55878C7313191958739EC6303C82BCB87CED1F384`.

The input is the repository's first-party
`fuzz/corpus/extraction_plan/seed.txt`, with its modification time fixed to
2000-01-01 00:00:00 UTC before capture. The producer command was:

```powershell
tar -acf C:\tmp\libarchive-oxide-lzip-fixture\bsdtar-seed.tar.lz `
  --format ustar --uid 0 --gid 0 --uname root --gname root `
  -C C:\tmp\libarchive-oxide-lzip-fixture seed.txt
```

The same bsdtar installation independently consumed the result with both
`tar -tf` and `tar -xOf`; it reported `seed.txt` and the expected
`safe/subdirectory/file.txt` payload. Tests do not invoke the external tool:
they decode the committed bytes through the public sync and async readers.

The duplicated `fuzz/corpus/codec_lzip/bsdtar-seed-tar.hex` record is the same
byte sequence for stable adversarial replay.
