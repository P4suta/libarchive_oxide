#!/bin/bash -eu
#
# Copyright 2026 libarchive_oxide contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

set -o pipefail

project_root="$SRC/libarchive_oxide"
target_triple="x86_64-unknown-linux-gnu"
target_dir="$WORK/cargo-fuzz-target"
binary_dir="$target_dir/$target_triple/release"

if [[ "${FUZZING_ENGINE:-libfuzzer}" != "libfuzzer" ]]; then
    echo "libarchive_oxide's Rust OSS-Fuzz integration supports libFuzzer only" >&2
    exit 1
fi
if [[ "${SANITIZER:-address}" != "address" ]]; then
    echo "libarchive_oxide's Rust OSS-Fuzz integration supports AddressSanitizer only" >&2
    exit 1
fi
if [[ "${ARCHITECTURE:-x86_64}" != "x86_64" ]]; then
    echo "libarchive_oxide's OSS-Fuzz integration supports x86_64 only" >&2
    exit 1
fi

cd "$project_root"

mapfile -t fuzz_targets < <(cargo fuzz list | LC_ALL=C sort)
source_target_count="$(
    find fuzz/fuzz_targets -maxdepth 1 -type f -name '*.rs' -printf '.' | wc -c
)"
if [[ "${#fuzz_targets[@]}" -ne "$source_target_count" ]]; then
    echo "cargo-fuzz target count does not match fuzz/fuzz_targets/*.rs" >&2
    exit 1
fi
if [[ "${#fuzz_targets[@]}" -ne 27 ]]; then
    echo "expected the reviewed 27-target OSS-Fuzz surface, found ${#fuzz_targets[@]}" >&2
    exit 1
fi

# cargo-fuzz supplies OSS-Fuzz's sanitizer instrumentation and libFuzzer link.
# The portable profile keeps every runtime dependency in the produced binary.
# Release optimization makes all 27 targets practical while debug assertions
# and overflow checks retain the fail-closed arithmetic paths used by local CI.
cargo fuzz build \
    --release \
    --debug-assertions \
    --no-default-features \
    --features portable-codecs \
    --sanitizer address \
    --target "$target_triple" \
    --target-dir "$target_dir"

for fuzz_target in "${fuzz_targets[@]}"; do
    install -m 0755 "$binary_dir/$fuzz_target" "$OUT/$fuzz_target"

    corpus_dir="$project_root/fuzz/corpus/$fuzz_target"
    if [[ ! -d "$corpus_dir" ]]; then
        echo "missing committed seed corpus directory for $fuzz_target" >&2
        exit 1
    fi
    if [[ -z "$(find "$corpus_dir" -type f -print -quit)" ]]; then
        echo "seed corpus directory for $fuzz_target is empty" >&2
        exit 1
    fi
    (
        cd "$corpus_dir"
        zip -q -r "$OUT/${fuzz_target}_seed_corpus.zip" .
    )

    cat > "$OUT/${fuzz_target}.options" <<'OPTIONS'
[libfuzzer]
max_len = 2097152
rss_limit_mb = 2048
timeout = 25
OPTIONS
done
