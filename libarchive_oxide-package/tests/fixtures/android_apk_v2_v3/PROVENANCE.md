# Android APK Signature Scheme v2/v3 fixture provenance

These APKs are copied byte-for-byte from the Android Open Source Project
`platform/tools/apksig` test resources at commit
`184702d9d18877edf9e5296c4e191cf0aa2b5fbb`.

Upstream path:

`src/test/resources/com/android/apksig/`

Immutable source prefix:

`https://android.googlesource.com/platform/tools/apksig.git/+/184702d9d18877edf9e5296c4e191cf0aa2b5fbb/src/test/resources/com/android/apksig/`

The upstream project and these fixtures are licensed under Apache-2.0. They
are produced and consumed by Google's reference `apksig`/`apksigner`
implementation and exercise RSA, ECDSA, v3 proof-of-rotation metadata, and
malformed signing-block failure cases. The v1-only fixtures additionally
exercise multiple JAR signer files and multiple CMS `SignerInfo` records,
including a block where one of two signer records has a wrong signature.

The targeted-rotation positive set covers v3 development-range overlap,
v3.1 release rotation at SDK 34, and v3.1 development rotation at SDK 10000.
The negative set covers a bad v3 lineage signature, an incorrect v3.1 lineage
key, a changed lineage digest, stripped v3.1 block or rotation-min-SDK
attribute, v3.1 without its mandatory v3 base block, and a mismatching
rotation-min-SDK value.

SHA-256:

- `2670d3a8ec0b5f0be3ac33527a3aa6704c244a1b86cb5e42a6b03596414df383`
  `golden-aligned-v2-out.apk`
- `6e606307a39c826330db293a63c677566265d593bcb9b5c6fa58b34f86102668`
  `golden-aligned-v3-out.apk`
- `9c6947bf9398a15e85a52bf83b07cfae6686ff49e03034d09cbea45a19bdaa15`
  `v1v2v3-with-rsa-2048-lineage-3-signers.apk`
- `04c8290687554d74b479f6a609306c999fd0011ffd38e3d96d102ca6eae4b304`
  `v2-only-apk-sig-block-size-mismatch.apk`
- `2b66deee0b1413ecf662b44dde40babbdde659d6e9a27351365f106076678208`
  `v2-only-signatures-and-digests-block-mismatch.apk`
- `f2b3533c9a7b2f50253730052b0b1cad431f010bda7ad6e20febf777594e31a1`
  `v2-only-with-ecdsa-sha256-p256.apk`
- `a40f823ac90d7ff366157923c689fc0eb14956354af647644b3148fc1ca3fe70`
  `v31-rsa-2048_2-tgt-33-1-tgt-28.apk`
- `96c72698d495c033d3576ade17079890ba92350c0f52ea7a4923ce4f39310e20`
  `v2-stripped.apk`
- `21357c0cc662102a9fb483680c4cc6e4f2142e1a83b6639126d454a4dafe5bdb`
  `v2-stripped-with-ignorable-signing-schemes.apk`
- `eb11cff7612213b97ec2a98ca1010adcc1470af20c268c66390f7cd6a585388e`
  `golden-rsa-verity-out.apk`
- `e8290cb28b53cd18b2b6bfc5f4d755fe757d6b67fb1d1262f327292a614fe3d8`
  `v2-only-with-ecdsa-sha256-p521.apk`
- `3ff2d8af31539b58de2bb3ca4c515c8fa540017291faa8209efa4a15c0035f6f`
  `v2-only-with-rsa-pkcs1-sha256-1024.apk`
- `ea25df6eea09bb75d605d18ca461d704edb432135c52f3aee2898c3c1b78733b`
  `v2-only-with-rsa-pkcs1-sha256-16384.apk`
- `f753f6d42052d12997e3650750e9d96f4a45b3cf31e650ec3c90ba6375233162`
  `v1-only-two-signers.apk`
- `88607535fb6468006ce69800aef3ba0f8112592016cf39701a6d9190360d924a`
  `v1-only-with-signed-attrs-signerInfo1-good-signerInfo2-good.apk`
- `676d0bb75c7641ea67023f6df3ba1d25d4286019e70e7841dd66d0cf918026ba`
  `v1-only-with-signed-attrs-signerInfo1-wrong-signature-signerInfo2-good.apk`
- `c482a68c316fe4b01ded141642bc5e397b170a6fef63437a276a835b5fe00d0d`
  `v3-rsa-2048_2-tgt-dev-release.apk`
- `e9c2fbf63c9d362ca8a1bbcddb0efb40728a2a588fbf60a4e615d6c4bc75697e`
  `v31-rsa-2048_2-tgt-10000-dev-release.apk`
- `5d6554386a76c453499b6bb6e3a4b183eb5098f89058fedbec101c39588edc6b`
  `v31-rsa-2048_2-tgt-34-1-tgt-28.apk`
- `d521755adb86006d8247da2e94f17f28067654b802f7350ca97dd668eadaa477`
  `v1v2v3-with-rsa-2048-lineage-3-signers-invalid-lineage-attr.apk`
- `26f7571dab499d3d9ef6e87ea0564e315f88ea5f593263aa54bb2e648d77c69c`
  `v31-2elem-incorrect-lineage.apk`
- `106005d2ccd13fd3bab80dded8ea7cadeafcea2747241e69ecbc04936660d5b4`
  `v31-2elem-lineage-incorrect-digest.apk`
- `111090e77fd28e61cf6caa3f8a165fbf5cc7cbf0408621eda9e061d8a18e3331`
  `v31-block-stripped-v3-attr-value-33.apk`
- `be7f11c1dab5f8eede79a779f2950848f0aef89f7f8396ee9943de50c92b2c97`
  `v31-tgt-33-no-v3-attr.apk`
- `2eb9627c2fea5e72c8c7f033ff73292a738b5da37f7137c989cea949115a4849`
  `v31-tgt-33-no-v3-block.apk`
- `0a57a59571d835c0fdbd768e9a1ea5e327a48f467a4c15d77e13afe642c634fe`
  `v31-tgt-34-v3-attr-value-33.apk`

No private signing keys are included.
