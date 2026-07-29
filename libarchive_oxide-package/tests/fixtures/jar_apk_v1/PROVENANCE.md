# JAR / Android APK v1 signature fixture provenance

`jar-apk-v1-signed.apk` is a deliberately small ZIP archive produced and
signed by OpenJDK's `jar`, `keytool`, and `jarsigner`. It is usable as both a
JAR signature interoperability fixture and an Android APK v1 (JAR signature
scheme) fixture.

The archive contains:

- `AndroidManifest.xml`
- `classes.dex`
- `META-INF/MANIFEST.MF`
- `META-INF/FIXTURE.SF`
- `META-INF/FIXTURE.RSA`

The Android members are minimal parser fixtures rather than an installable
application. The root `AndroidManifest.xml` and payload member satisfy this
repository's Android APK structural profile; the cryptographic layout is a
real APK v1/JAR signature produced by `jarsigner`.

## Producer

- Generated: 2026-07-29
- Container image: Fedora 43, local image ID
  `sha256:762d73ba1c455232b0272c5d445a34f36c4b9f421cbc05ce8102552325b6a222`
- Package: `java-21-openjdk-devel-21.0.11.0.10-2.fc43.x86_64`
- Runtime:
  `OpenJDK 64-Bit Server VM (Red_Hat-21.0.11.0.10-2) (build 21.0.11+10)`
- Key: 2048-bit RSA
- Entry digest: SHA-256
- Signature algorithm: SHA256withRSA
- Signer:
  `CN=libarchive-oxide JAR APK v1 fixture, O=libarchive-oxide, C=JP`

## Generation

The input directory contained the two application members listed above.
The PKCS#12 keystore and exported certificate were created in an isolated
temporary directory outside the repository and were not committed.

```sh
dnf install -y --setopt=install_weak_deps=False java-21-openjdk-devel

jar --create --file unsigned.apk -C input .

keytool -genkeypair \
  -alias fixture \
  -keystore fixture-java21.p12 \
  -storetype PKCS12 \
  -storepass changeit \
  -keypass changeit \
  -keyalg RSA \
  -keysize 2048 \
  -sigalg SHA256withRSA \
  -dname "CN=libarchive-oxide JAR APK v1 fixture, O=libarchive-oxide, C=JP" \
  -validity 3650 \
  -noprompt

jarsigner \
  -keystore fixture-java21.p12 \
  -storetype PKCS12 \
  -storepass changeit \
  -keypass changeit \
  -digestalg SHA-256 \
  -sigalg SHA256withRSA \
  -sigfile FIXTURE \
  -signedjar jar-apk-v1-signed.apk \
  unsigned.apk \
  fixture

keytool -exportcert \
  -alias fixture \
  -keystore fixture-java21.p12 \
  -storetype PKCS12 \
  -storepass changeit \
  -file signer-cert.der

jarsigner -verify -verbose -certs jar-apk-v1-signed.apk
sha256sum jar-apk-v1-signed.apk signer-cert.der
```

`jarsigner -verify` reported `jar verified.` and identified both the digest
and signature algorithms above. It also reports the expected warnings that
the fixture certificate is self-signed, has no trusted certification path,
and has no timestamp. Those warnings are intentional: certificate trust is
tested separately by pinning the certificate fingerprint.

## Digests

- Artifact SHA-256:
  `f1bd2ed4efddf7742eeeac6ddb0bc3dc710824c5734a5ba42fc7a88b589f9bf5`
- Signer certificate SHA-256 (DER bytes):
  `06f73dd845505562148c9b2d658ce359a3f6e86bdc096960826ba04d0b2e4182`
- Artifact size: 2632 bytes
