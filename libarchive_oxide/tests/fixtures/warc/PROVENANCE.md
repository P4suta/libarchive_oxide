<!-- SPDX-FileCopyrightText: 2026 libarchive_oxide contributors -->
<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# WARC fixture provenance

`iipc-annex-b-metadata.hex` is a hexadecimal encoding of a WARC 1.1
`metadata` record independently assembled from Annex B.4 of the IIPC-hosted
ISO 28500:2017 WARC 1.1 specification:

<https://iipc.github.io/warc-specifications/specifications/warc-format/warc-1.1/#example-of-metadata-record>

The named fields and sample `application/warc-fields` content follow that
published example. The fixture makes the standard's required CRLF bytes
explicit and recalculates `Content-Length` as 65 for the three complete CRLF
body lines. It is stored as text hex so repository line-ending conversion
cannot alter the interoperable WARC bytes. The decoded fixture is 444 bytes
with SHA-256
`de9780fcf2b4622ae3bcf15409964288f72c534d53a6aed160ed867df9b4d54e`.

The fixture is specification-derived test data, contains no user data, and is
covered by the repository's `REUSE.toml` test-fixture override.
