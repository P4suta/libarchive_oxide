# libarchive_oxide-package

Offline, bounded software-package inspection for `libarchive_oxide`.

The crate owns ecosystem rules while `libarchive_oxide` supplies archive
entries. `PackageInspector` reports structural conformance. `PackageVerifier`
returns integrity, signature validity, and issuer trust as independent
dimensions; `not-evaluated` is never presented as success, and no API performs
implicit network access.

Implemented structural profiles include Debian deb, RPM payloads, JAR, NuGet,
Wheel, EPUB, Android APK, IPA, MSIX, and Alpine APK v2. Alpine and Android APK
use the unambiguous IDs `alpine-apk` and `android-apk`. JAR SHA-2 manifest
digests and Wheel `RECORD` hashes and sizes are verified over streamed entry
bytes. JAR and Android APK v1 signatures additionally verify the `.SF`
whole-manifest, main-attributes, and individual-section SHA-2 digests over the
specification's exact folded-line bytes, every CMS `SignedData` signer and
signed `messageDigest`, and expose the SHA-256 fingerprint of each verified
signer certificate. Section digests are used as the specified fallback when
another signer has changed the manifest, while APK v1 additionally requires
every signer to cover every payload entry. Android APK v2/v3 verifies bounded
Signing Block RSA-PSS, RSA-PKCS#1, and P-256/P-384 ECDSA-with-SHA-256
signatures. It streams the specification's 1 MiB chunked SHA-256/SHA-512
digests and the 4 KiB salted fs-verity SHA-256 tree over the virtual APK outside
the Signing Block, including the required EOCD central-directory offset
rewrite. Standard and fs-verity records may coexist, and every digest kind
selected by the authenticated SDK-range policy is compared. The AOSP
platform-range policy is applied to each signer: standard algorithms start at Android
N, fs-verity algorithms at Android P, the strongest record at each represented
introduction level is selected, and every selected signature must verify.
Authenticated APK v1
`X-Android-APK-Signed` metadata is also enforced so removing a required v2/v3
block cannot downgrade a verified v1 package. When v1 and v2/v3 coexist, every
detected scheme is evaluated and a valid scheme cannot hide another scheme's
invalid, unsupported, or unevaluated result.

APK v3 proof-of-rotation version 1 verifies at most 64 lineage certificates:
each predecessor certificate and declared algorithm must authenticate the next
level, duplicate certificates are rejected, and the terminal certificate must
be the active signer. v3/v3.1 targeted signers additionally enforce
authenticated SDK ranges, contiguous release/development boundaries, the
rotation-min-SDK stripping attribute, mandatory v3/v3.1 coexistence, and
lineage-prefix extension across the rotation boundary.
`AndroidApkRotationReport` exposes signer ranges, development markers,
certificate fingerprints, flags, and signature-algorithm IDs without turning
lineage ancestors into trust roots.

Android APK Signature Scheme v4/v4.1 detached `.idsig` files are verified only
through the explicit
`PackageVerifier::android_apk_with_v4_sidecar(apk, idsig)` API. The verifier
never derives a sibling path and never performs network I/O. It bounds the
incremental-fs header, every signing-info field, signer count, and serialized
Merkle tree; verifies every sidecar signature and certificate/SPKI identity;
binds the primary signer and preferred authenticated digest to verified v3 (or
v2 when v3 is absent); and binds the v4.1 signing-info block to the exact v3.1
signer. The SHA-256 fs-verity-compatible tree and root are recomputed over every
raw APK byte. `AndroidApkV4Report` keeps sidecar integrity, signature validity,
offline trust, signer fingerprints, and typed findings separate. Omitting the
optional sidecar produces `not-evaluated`, never success, and supplying one
explicitly never grants trust.

Alpine APK v2
verifies `.SIGN.RSA`, `.SIGN.RSA256`, and
`.SIGN.RSA512` against the exact compressed control gzip member using
caller-supplied public keys, then checks `.PKGINFO datahash` against the exact
compressed data member. The legacy no-`datahash` combined scope is explicitly
unsupported rather than silently approximated. `TrustPolicy` compares verified
fingerprints only with caller-supplied offline pins; supplying a verification
key never trusts it. A valid but untrusted signature therefore has
`signature_validity = verified` and `trust = invalid`. RPM `PAYLOADSHA256`,
`PAYLOADSHA512`, and `PAYLOADSHA3_256`
declarations are checked over the compressed payload with constant-memory
hashing. Their uncompressed `ALT` forms are also checked when the payload is
both declared and detected as uncompressed; compressed `ALT` coverage remains
explicitly unsupported.

NuGet signature format v1 is verified offline over the specification's
canonical classic-ZIP byte stream. The verifier accepts RSA/SHA-256,
RSA/SHA-384, and RSA/SHA-512 author or repository primary signatures, validates
`SigningCertificateV2` and commitment-type attributes, and validates the
single repository countersignature allowed on an author signature. ZIP64 and
multi-disk packages are rejected because NuGet v1 does not define a signing
transform for them. The `.signature.p7s` member must be final, stored, and use
the exact non-UTF-8-flagged root name; `.nuspec` fields, duplicate names,
Unicode-normalized case collisions, and all signature metadata remain bounded.

```rust,no_run
use std::fs::File;

use libarchive_oxide_package::{
    AlpineRsaPublicKey, PackageVerifier, TrustPolicy, VerificationDimension,
};

let key_id = b"alpine-devel@example.org-12345678.rsa.pub".to_vec();
let key = AlpineRsaPublicKey::from_pem(key_id, std::fs::read("signer.rsa.pub")?)?;
let pin = key.fingerprint_sha256();
let report = PackageVerifier::new(
    TrustPolicy::offline().with_trusted_signer_sha256(pin),
)
.with_alpine_rsa_public_key(key)
.alpine_apk(File::open("package.apk")?);
assert_eq!(report.signature_validity(), VerificationDimension::Verified);
assert_eq!(report.trust(), VerificationDimension::Verified);
# Ok::<(), Box<dyn std::error::Error>>(())
```

```rust,no_run
use std::fs::File;

use libarchive_oxide_package::{PackageVerifier, VerificationDimension};

let report = PackageVerifier::default().android_apk_with_v4_sidecar(
    File::open("application.apk")?,
    File::open("application.apk.idsig")?,
);
let v4 = report.android_apk_v4().ok_or("missing Android v4 report")?;
assert_eq!(v4.integrity(), VerificationDimension::Verified);
assert_eq!(v4.signature_validity(), VerificationDimension::Verified);
# Ok::<(), Box<dyn std::error::Error>>(())
```

CMS input, APK Signing Block values, APK v4 sidecar headers/signing infos/Merkle
trees, signer/certificate/record counts, ASN.1 nesting, content-digest buffers,
Alpine key/signature material, exact compressed-member capture, and retained
metadata are bounded.
Malformed or mismatching signatures report `invalid`; JAR/APK v1 SHA-1 and
algorithms outside that verifier's modern policy report `unsupported`.
Android v2/v3 DSA, ECDSA-with-SHA-512/P-521, RSA keys outside the current
2048..=8192-bit backend boundary, and unknown proof-of-rotation algorithms
remain explicit `unsupported`; they are never silently approximated. This
verifier authenticates the v3/v3.1 signer ranges and their rotation boundary,
and consolidates the signature-algorithm winners for those authenticated
ranges. It does not yet parse binary `AndroidManifest.xml` SDK declarations or
prove installability across the manifest's complete Android platform range.
The interoperability suite uses OpenJDK `jarsigner`
output and official AOSP CTS/`apksig` v1/v2/v3/v3.1/v4/v4.1 fixtures,
including multiple signer files, multiple CMS `SignerInfo` records, malformed
or cyclic lineage, stripped rotation metadata, digest mismatch, resource
boundaries, and tampering.
MSIX/APPX `AppxBlockMap.xml` is parsed without a DOM under the shared
allocation, nesting, path, entry-count, and decoded-byte budgets. The verifier
requires exact non-footprint-file coverage (including `AppxManifest.xml`),
rejects duplicate/colliding/traversing names, and checks declared file and
local-header sizes plus SHA-256 over exact streamed 64-KiB uncompressed blocks.
Microsoft MSIX SDK fixtures cover stored/deflated and multi-block inputs.
The encrypted/delta 2015 and 2017 BlockMap vocabularies are a typed
`unsupported` result rather than being parsed as the implemented 2010
vocabulary.
`AppxSignature.p7x` is detected but its CMS signature remains
`not-evaluated`; signature detection by itself never produces cryptographic
success.

Licensed under either MIT or Apache-2.0, at your option.
