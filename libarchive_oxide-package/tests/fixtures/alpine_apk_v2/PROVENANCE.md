# Alpine APK v2 RSA fixture provenance

The positive interoperability fixture is the unmodified Alpine Linux
`alpine-keys-2.5-r0.apk` package for Alpine v3.22 `x86_64`. It was produced by
Alpine's `abuild`, not by this repository.

- Package source:
  <https://dl-cdn.alpinelinux.org/alpine/v3.22/main/x86_64/alpine-keys-2.5-r0.apk>
- Public-key source: `etc/apk/keys/alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub`
  inside the same official package
- Retrieved: 2026-07-29
- Package size: 13,390 bytes
- Package SHA-256:
  `1069fa68769607690e46b0d689f1ad9b5e346be2752ece313685b4f29ec70e25`
- Public-key PEM SHA-256:
  `207e4696d3c05f7cb05966aee557307151f1f00217af4143c1bcaf33b8df733f`
- Canonical PKCS#1 public-key DER SHA-256:
  `5e03bee6b12094ef8e01323d8efa0d5929487c781def110fb2e8d09fc446f899`
- Signature member:
  `.SIGN.RSA.alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub`
- `.PKGINFO` compressed-data SHA-256:
  `c72f1654a3503e252d02681b55c7074c6620310333523d8830ec3edb199e5327`
- Embedded package license metadata: `MIT`

The negative wrong-key fixture is
`alpine-devel@lists.alpinelinux.org-61666e3f.rsa.pub` from that same
`alpine-keys-2.5-r0.apk`. Its PEM SHA-256 is
`128d34d4aec39b0daedea8163cd8dc24dff36fd3d848630ab97eeb1d3084bbb3`.

## Independent verification

On 2026-07-29, Alpine `apk-tools` independently accepted the checked-in
package and supplied key:

```text
docker run --rm -v "<fixture-dir>:/fixtures:ro" \
  alpine@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce \
  apk verify --keys-dir /fixtures /fixtures/alpine-keys-2.5-r0.apk

/fixtures/alpine-keys-2.5-r0.apk: 0 - OK
```

The tests additionally mutate, one at a time, the exact compressed control
member, the compressed data member, and the signature body. They also replace
the verification key and reduce the metadata/capture budget. This proves that
the positive result is not merely signature-member detection.

The binary package and extracted public keys are redistributed under the
fixture package's MIT license; the directory-specific `REUSE.toml` annotation
records that provenance.
