# CLI package fixture provenance

These byte-for-byte copies keep the independently packaged
`libarchive_oxide-cli` crate's explicit `package_cli` integration test
self-contained.

- `jar-apk-v1-signed.apk` is copied from
  `libarchive_oxide-package/tests/fixtures/jar_apk_v1/`; its OpenJDK producer,
  command, signer, and SHA-256 are recorded in that directory's
  `PROVENANCE.md`.
- `alpine-keys-2.5-r0.apk` and
  `alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub` are copied from
  `libarchive_oxide-package/tests/fixtures/alpine_apk_v2/`; their Alpine mirror
  URLs, MIT license, hashes, canonical key fingerprint, and independent
  `apk-tools` verification are recorded in that directory's `PROVENANCE.md`.
- `android-apk-v2-aosp.apk` is copied from
  `libarchive_oxide-package/tests/fixtures/android_apk_v2_v3/`. It is the
  Apache-2.0 AOSP `apksig` `golden-aligned-v2-out.apk` fixture at commit
  `184702d9d18877edf9e5296c4e191cf0aa2b5fbb`, with SHA-256
  `2670d3a8ec0b5f0be3ac33527a3aa6704c244a1b86cb5e42a6b03596414df383`.
- `android-apk-v31-rotation-aosp.apk` is copied from
  `libarchive_oxide-package/tests/fixtures/android_apk_v2_v3/`. It is the
  Apache-2.0 AOSP `apksig` `v31-rsa-2048_2-tgt-34-1-tgt-28.apk` fixture at
  commit `184702d9d18877edf9e5296c4e191cf0aa2b5fbb`, with SHA-256
  `5d6554386a76c453499b6bb6e3a4b183eb5098f89058fedbec101c39588edc6b`.
- `android-apk-standard-verity-aosp.apk` is copied from
  `libarchive_oxide-package/tests/fixtures/android_apk_v2_v3/`. It is the
  Apache-2.0 AOSP `apksig` `golden-rsa-verity-out.apk` fixture at commit
  `184702d9d18877edf9e5296c4e191cf0aa2b5fbb`, with SHA-256
  `eb11cff7612213b97ec2a98ca1010adcc1470af20c268c66390f7cd6a585388e`.
- `android-apk-v4-cts.apk` and `android-apk-v4-cts.apk.idsig` are copied from
  `libarchive_oxide-package/tests/fixtures/android_apk_v4/`. They are the
  Apache-2.0 AOSP CTS v4.0 reference pair from `platform/cts` commit
  `79e7fb0fabd62276c5662b5000ac47ac18f2749f`; their SHA-256 values are
  `36e6594259ce226f1e4597e513e5985dbb94fde23f5aba6b3405656b435be8c4`
  and
  `e444deb5b0a3bf6706c479d9d9f8bff7d87116d3391121561cda858e0ed64f0c`.
- `msix-authenticode-microsoft.appx` is copied from
  `libarchive_oxide-package/tests/fixtures/msix_blockmap/SignedUntrustedCert.appx`.
  It is Microsoft's MIT-licensed SDK fixture with SHA-256
  `e0f94c16eab4d7acfb41b1dc23acd8c65d23e71a1805061343e4f4ac7018e34e`;
  its upstream URL and Authenticode expectations are recorded in that
  directory's `PROVENANCE.md`.
- `ipa-rcodesign-signed.ipa` is copied from
  `libarchive_oxide-package/tests/fixtures/ipa_codesign/rcodesign-signed.ipa`.
  It is the project-authored rcodesign 0.29.0 fixture with SHA-256
  `53b151628ae007db595e71de9083957b4027d73c9614c689d735f152fbb2ae59`;
  the exact producer command and combined MPL-2.0/project license are recorded
  in that directory's `PROVENANCE.md`.
- `rpm-signed.rpm` and `rpm.org-rsa-2048-test.pub` are copied from the RPM
  project's GPL-2.0-or-later test data at commit
  `ac5062c43e2337fb43a9179f02c0cc5d7d069802`. Their SHA-256 values are
  `d32735351a8952afc9e4afd7309e3a1929288eff5af32526934314f1f304ff7f`
  and `0a2f43cf43e170f9c42a62c329641945111fb535b137c1b746ec5e24307179b1`;
  upstream URLs are recorded in
  `libarchive_oxide-package/tests/fixtures/rpm_signature/PROVENANCE.md`.

The copies are intentionally checked by `xtask package-smoke`: no test in the
published crate source may reach outside its own package boundary.
