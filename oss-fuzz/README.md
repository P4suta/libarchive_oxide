<!--
SPDX-FileCopyrightText: 2026 libarchive_oxide contributors

SPDX-License-Identifier: MIT OR Apache-2.0
-->

# OSS-Fuzz integration bundle

This directory is the proposed `projects/libarchive-oxide` bundle for the
upstream [google/oss-fuzz](https://github.com/google/oss-fuzz) repository. It is
kept here beside the fuzz targets so target additions and resource policies can
be reviewed together. No OSS-Fuzz registration, external push, or network
service enrollment is performed by this repository.

Before an upstream submission, a maintainer must confirm that the
`primary_contact` address in `project.yaml` is attached to a Google account, as
required for OSS-Fuzz issue and ClusterFuzz access.

## Build contract

The bundle follows OSS-Fuzz's Rust integration:

- `Dockerfile` derives from `base-builder-rust`, clones the canonical repository,
  and installs only `zip` for seed-corpus packaging.
- `build.sh` lets `cargo-fuzz` provide libFuzzer and AddressSanitizer
  instrumentation, builds the additive portable-codec profile, and copies all
  extensionless binaries into `$OUT`.
- `cargo fuzz list` is the executable inventory. The build fails if it differs
  from the 27 reviewed source targets, so a target cannot silently miss
  continuous fuzzing.
- Each `<target>_seed_corpus.zip` is built from `fuzz/corpus/<target>`.
  Corpus licensing and origin are recorded in
  `fuzz/corpus/PROVENANCE.md`.
- Each target receives the same initial ClusterFuzz policy: 2 MiB maximum input,
  2 GiB process RSS, and a 25-second per-input timeout. The harnesses impose
  substantially tighter decoded-data and allocation limits internally.

The Rust `cargo-fuzz` integration declares only its supported `libfuzzer` +
`address` combination. This bundle additionally limits the reviewed build to
`x86_64`. Portable codecs avoid runtime shared-library assumptions on
ClusterFuzz workers.

## Local upstream-style validation

From a checkout of `google/oss-fuzz`, copy this directory and use the official
helpers:

```sh
cp -R /path/to/libarchive_oxide/oss-fuzz \
  projects/libarchive-oxide
python3 infra/helper.py build_image libarchive-oxide
python3 infra/helper.py build_fuzzers \
  --sanitizer address --engine libfuzzer \
  --mount_path /src/libarchive_oxide \
  libarchive-oxide /path/to/libarchive_oxide
python3 infra/helper.py check_build libarchive-oxide
python3 infra/helper.py run_fuzzer \
  --corpus-dir=/tmp/libarchive-oxide-corpus \
  libarchive-oxide read_tar
```

The final positional argument to `build_fuzzers` mounts the unmerged local
checkout over the clone made by the Dockerfile; `--mount_path` makes that
destination explicit and works consistently with Docker Desktop. Omit both
arguments when validating the already-merged `main` branch.

## Relationship to repository CI

The three layers are complementary:

1. Stable workspace tests replay every committed seed and deterministic mutation
   through `fuzz_lib` on portable and native profiles.
2. The Linux nightly GitHub job builds all targets and runs short portable/native
   libFuzzer campaigns, catching harness and backend-integration regressions
   before merge.
3. OSS-Fuzz continuously evolves long-lived corpora under the portable,
   self-contained AddressSanitizer build.

OSS-Fuzz findings should first be reproduced with `cargo +nightly fuzz run
<target> <artifact>`, then minimized and committed as a regression seed when its
license and provenance are known.
