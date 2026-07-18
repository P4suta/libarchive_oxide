---
name: Bug report
about: A crash, incorrect output, or other misbehavior (not a security issue)
title: ""
labels: bug
assignees: ""
---

<!--
For security vulnerabilities (crashes/hangs/OOM on untrusted archives), do NOT file here — use
GitHub's private vulnerability reporting instead: see SECURITY.md.
-->

## Summary

A clear, one-line description of the problem.

## Reproduction

Steps, code, or a command line that triggers it. Attach a minimal input archive if the bug depends
on a specific byte layout (a `.tar`/`.zip`/`.7z`/`.iso` fixture, ideally the smallest that reproduces).

```rust
// minimal snippet, or the exact CLI invocation (oxtar / oxcpio / oxcat / oxunzip)
```

## Expected vs. actual

- **Expected:**
- **Actual:**

## Environment

- libarchive_oxide version / commit:
- Crate(s): (e.g. `libarchive_oxide`, `libarchive_oxide-core`, `libarchive_oxide-cli`)
- Rust / OS:
- Feature flags: (e.g. default, `aes`, `sevenz`, `no-default-features`)
