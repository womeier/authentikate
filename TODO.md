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
- [ ] Consider extracting the JSON layer as a standalone Rocq library
  (`rocq-json`): the parser, canonical printer, accessors, `parse_print`,
  `parse_json_ok`, `get_str_ok` and the fuel measure, over a lower layer with
  the bytestring algebra and decimal/`N`. The cut is clean -- `Json.v` and
  `JsonProofs.v` import only `Bytes`, nothing points back at them, and they use
  none of `dot`, `split_on`, `join`, `bytes_eqb_eq` or `bytes_append_inj_l`, so
  the split runs through the middle of `Bytes.v`. `rocq-base64` is already
  consumed in exactly that shape. Against it: a second self-maintained flake
  input makes every proof edit a two-repo operation with a hash bump between
  the halves, and the restrictive subset (no escapes, printable ASCII,
  duplicate keys rejected, no arrays, null or floats, 16 fuel, 32-digit
  numerals) is a threat-model decision a published library invites pressure to
  relax -- relaxing escapes would break the `ok_string` no-injection reasoning
  in `Proofs.v`. Extraction also pins the style: `Set`-level, total, `N` not
  `nat`, no classes or monads. Cheap first step, and the only part that can go
  wrong: split `Bytes.v` in place into the JSON half and the JWT half and
  compile `Json.v` and `JsonProofs.v` against the JSON half alone.
