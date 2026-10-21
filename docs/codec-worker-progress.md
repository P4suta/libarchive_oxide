# Bounded codec worker progress

`filter::xz::XzDecoder::drive` and `filter::lzip::LzipDecoder::drive` retain input when their bounded worker queue is full.
If the worker subsequently requests input, the owner must retry that retained input before waiting for another worker event.
Input requests, produced bytes, and worker completion remain distinct `WorkerProgress` variants until the driver has made that decision.
Completion still counts as observable progress for asynchronous callers.
Queue capacity, format validation, input limits, and error behavior are unchanged.

The regression in `filter::worker::testing::assert_retained_input_progress` schedules the production driver at the full-input boundary.
It drains the two queued input messages, emits `NeedInput`, and then releases the driver.
The driver must deliver its retained bytes and return `NeedInput` without another blocking receive.
Channels and barriers select this interleaving without sleeps, elapsed-time verdicts, or global test switches.
Both adapter tests failed with `owner waited after consuming an input request` before their fixes and pass after the fixes.
The tests run in the normal portable and native `just test-ci` profiles.

```sh
mise x -- cargo test --locked -p libarchive_oxide --lib --no-default-features --features xz,lzip input_request_retries_retained_bytes_before_waiting
```

The observed XZ interoperability test also passes all 64 fixed-count iterations after the fix.
Its original inputs, chunk boundaries, and nextest timeout remain unchanged.

```sh
mise x -- cargo nextest run --profile ci -p libarchive_oxide --test stream_v2 --no-default-features --features portable-codecs,aes,sevenz,async,tokio --test-threads 1 --stress-count 64 -E 'test(=selected_xz_writer_is_deterministic_and_interoperable)'
```

This is native fault-injection evidence for the identified interleaving, plus a finite interoperability check.
It does not establish progress for every possible thread schedule.
The adapter relies on Rust's [bounded channel ordering and disconnection semantics](https://doc.rust-lang.org/std/sync/mpsc/fn.sync_channel.html), barrier synchronization, and eventual OS scheduling.
The existing parser and bounds logic is outside this change.
The exhaustive enum matches preserve event identity without adding a separate decision algorithm.
[Kani does not support concurrent execution](https://model-checking.github.io/kani/rust-feature-support.html#concurrency), so a sequentialized channel harness would not establish the affected progress property.
Reassess this limitation when a verifier can cover the production standard-library channels and thread scheduling, or when the worker transport changes.
