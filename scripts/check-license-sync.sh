#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
crates=(
  libarchive_oxide-core
  libarchive_oxide
  libarchive_oxide-cli
)
licenses=(
  Apache-2.0.txt
  MIT.txt
)

for crate in "${crates[@]}"; do
  for license in "${licenses[@]}"; do
    source_file="$repo_root/LICENSES/$license"
    crate_file="$repo_root/$crate/LICENSES/$license"
    if ! cmp -s "$source_file" "$crate_file"; then
      echo "license copy is stale: $crate/LICENSES/$license" >&2
      echo "copy LICENSES/$license into $crate/LICENSES/$license" >&2
      exit 1
    fi
  done
done

echo "all crate license copies match the repository license texts"
