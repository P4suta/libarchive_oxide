<!--
SPDX-FileCopyrightText: 2026 libarchive_oxide contributors

SPDX-License-Identifier: MIT OR Apache-2.0
-->

# Microsoft MSIX SDK block-map fixture provenance

These packages are copied byte-for-byte from Microsoft’s MIT-licensed
[`microsoft/msix-packaging`](https://github.com/microsoft/msix-packaging)
reference SDK at commit
`efeb9dad695a200c2beaddcba54a52c8320bd135`.

Upstream paths:

- `src/test/testData/unpack/platforms/TestWindows.msix`
- `src/test/testData/unpack/SignedUntrustedCert-CERT_E_CHAINING.appx`

`TestWindows.msix` is a compact unsigned package produced for the Microsoft
SDK’s platform-manifest tests. `SignedUntrustedCert.appx` contains a multi-block
deflated payload and an intentionally untrusted certificate; it is used here
only to prove block-map interoperability. This project does not treat the
presence of its `AppxSignature.p7x` as cryptographic signature validity.

SHA-256:

- `f9b5c5a4a43a31557242c34c1c2cd74bc04671da70fb8b6ad25d45691160ea61`
  `TestWindows.msix`
- `e0f94c16eab4d7acfb41b1dc23acd8c65d23e71a1805061343e4f4ac7018e34e`
  `SignedUntrustedCert.appx`

No private signing keys are included.
