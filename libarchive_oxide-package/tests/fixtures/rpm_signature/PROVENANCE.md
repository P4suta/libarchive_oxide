<!--
SPDX-FileCopyrightText: 2026 libarchive_oxide contributors

SPDX-License-Identifier: MIT OR Apache-2.0
-->

# RPM signature fixtures

The binary packages and public certificates in this directory are copied from the upstream RPM project's test data at commit `ac5062c43e2337fb43a9179f02c0cc5d7d069802`, retrieved on 2026-08-15:

- <https://github.com/rpm-software-management/rpm/tree/master/tests/data/RPMS>
- <https://github.com/rpm-software-management/rpm/tree/master/tests/data/keys>

They are used to cross-check the bounded Safe Rust verifier against RPM's own `rpmkeys` expectations.
Upstream distributes the test data under GPL-2.0-or-later.
The repository's `REUSE.toml` records that license separately from this project's implementation.

| file | SHA-256 |
| --- | --- |
| `alice.asc` | `aec5756488daef30c8c37d2ac5ae9c8c9e050bb236ba4aba3feb4564319a5b58` |
| `hello-2.0-1.x86_64-signed-with-subkey.rpm` | `e94d858ebf1cca074b17df5c2009a8ee52617a8df51b57f4fcc843b9fda33270` |
| `hello-2.0-1.x86_64-signed.rpm` | `d32735351a8952afc9e4afd7309e3a1929288eff5af32526934314f1f304ff7f` |
| `hello-2.0-1.x86_64-v3-signed.rpm` | `0bc835540979860dd90a40f5fc8c159b968d56a070769a47bd188fb33e84f2ee` |
| `rpm.org-rsa-2048-test.pub` | `0a2f43cf43e170f9c42a62c329641945111fb535b137c1b746ec5e24307179b1` |
