#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
#
# SPDX-License-Identifier: MIT OR Apache-2.0

# Mechanical guard for the static-dispatch invariant. The sole exception is the exact
# `std::error::Error::source` method signature mandated by the standard library; it borrows a
# concrete stored error and does not introduce owned type erasure or runtime format/codec dispatch.
# Comment lines are ignored. Every other `dyn` hit fails.
set -euo pipefail

if rg -n '\bdyn\b' libarchive_oxide-core/src libarchive_oxide/src libarchive_oxide-cli/src \
  | rg -v '^[^:]+:[0-9]+:\s*//' \
  | rg -v "fn source\\(&self\\) -> Option<&\\(dyn std::error::Error \\+ 'static\\)> \\{"; then
  echo "check-no-dyn: found 'dyn' in library source (type erasure is forbidden)" >&2
  exit 1
fi
echo "check-no-dyn: OK (static dispatch; only std::error::Error::source signatures use dyn)"
