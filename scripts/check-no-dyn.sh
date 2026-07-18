#!/usr/bin/env bash
# Mechanical guard for the "zero type erasure" invariant: no `dyn` (Box<dyn>, &mut dyn, &dyn,
# or bare dyn) may appear in library/binary source. Comment lines are ignored. A hit fails.
set -euo pipefail

if rg -n '\bdyn\b' arca-core/src arca-filter/src arca/src arca-cli/src | rg -v '^\s*//'; then
  echo "check-no-dyn: found 'dyn' in library source (type erasure is forbidden)" >&2
  exit 1
fi
echo "check-no-dyn: OK (no dyn in library source)"
