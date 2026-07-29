# NuGet repository-signature fixture provenance

`nuget.common.6.0.0.nupkg` is the unmodified `NuGet.Common` 6.0.0 package
downloaded from NuGet.org's official V3 flat-container endpoint on
2026-07-29:

`https://api.nuget.org/v3-flatcontainer/nuget.common/6.0.0/nuget.common.6.0.0.nupkg`

- Size: 247,332 bytes
- SHA-256:
  `f92cc2c40f6cc9462dee4e1e89c15154b144fe884e9d60cc76a4bcff45af7b6d`
- Package repository:
  `https://github.com/NuGet/NuGet.Client`
- Package repository commit recorded by the `.nuspec`:
  `e0edb52d2ee204ab1117c9a592addc705cc76471`
- License expression recorded by the `.nuspec`: `Apache-2.0`

The root `.signature.p7s` contains an RSA/SHA-256 author primary signature and
a NuGet.org repository countersignature, both using CMS
SubjectKeyIdentifier signer identifiers. The positive test verifies both
signatures, the authenticated canonical package hash, and two distinct signer
certificate fingerprints without network access. Derived in-memory cases
cover a signed-byte tamper, malformed CMS with a valid ZIP CRC, an incorrect
trust pin, and a signature metadata budget failure; no modified binary fixture
is committed.
