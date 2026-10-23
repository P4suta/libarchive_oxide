# SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

if type == "array" then
  length == $expected_count and all(.[]; . == $expected_result)
else
  false
end
