# Deferred Work

- [ ] Replace `components/service/build.mjs`'s internal `wasm-merge` step with explicit
  component-model wiring of the generated core module and adapters. Retain the
  current merge for now; Rust crypto/email providers already use component-level
  composition.
- [ ] Make CertiRocq's memory-growth helper honor `required_bytes`, leave
  `mem_ptr` unchanged, and grow enough pages, with overflow and failure handling.
  Preserve compiler headroom by having generated checks request
  `max(required_bytes, 65536)` and update static headroom accounting accordingly.
- [ ] Once the helper semantics are fixed, simplify adapter allocation glue to
  use the exported helper and add allocation/growth regression tests.
- [ ] Move the host's `wasi:keyvalue/store` implementation into a separate storage
  component and wire it into the service through `host/composition.wac`. Preserve
  account state across fresh per-request component instances, preferably with a
  file-backed store and narrowly scoped host-granted filesystem access; an
  in-memory provider would require a separate, long-lived instance. Keep signup
  serialization unless the get-then-set operation is made atomic.
