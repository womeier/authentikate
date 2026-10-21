# Deferred Work

- [ ] Replace `component/build.mjs`'s internal `wasm-merge` step with explicit
  component-model wiring of the generated core module and adapters. Retain the
  current merge for now; Rust crypto/email providers already use component-level
  composition.
- [ ] Make CertiRocq's memory-growth helper honor `required_bytes`, leave
  `mem_ptr` unchanged, and grow enough pages, with overflow and failure handling.
  Preserve compiler headroom by having generated checks request
  `max(required_bytes, 65536)` and update static headroom accounting accordingly.
- [ ] Once the helper semantics are fixed, simplify adapter allocation glue to
  use the exported helper and add allocation/growth regression tests.
- [ ] Revisit the postponed revert of the CertiRocq pin from `cb74dd6b` to the
  previous revision `6d34b50bfea92aece62712ae120890c9fda8e514`. The pin remains
  unchanged until this work is resumed.
