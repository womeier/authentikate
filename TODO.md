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
  in-memory provider would require a separate, long-lived instance. Signup no
  longer depends on that serialization -- it creates through the atomic CAS --
  but a file-backed provider still has to implement `cas`/`swap` atomically.
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
- [ ] If the component model is ever mechanized to cover this artifact, layer it
  deliberately. The shipped thing is a composition -- `host/composition.wac`
  wires the service to the Argon2, Ed25519 and stdout-email components -- so
  wac-style linking belongs inside the mechanization, not beyond it: a theorem
  about one component in isolation says nothing about what runs. Three layers,
  and the decision is which of them get Iris.
  - An **Iris-free operational semantics**: component structure, index spaces,
    aliases, instantiation as a topological evaluation of the definition graph,
    canonical ABI lift/lower, resource tables, and the step relation for a
    composed component. Iris-free because of who else needs it -- a verified
    interpreter, differential testing against the component model's own Python
    canonical-ABI reference, and above all extending CertiRocq's backend
    theorem across foreign calls, which relates source evaluation to module
    execution and wants no separation logic. This layer also has to be readable
    beside the spec document by someone who will never use Iris.
  - **Two capability lemmas, by direct induction.** Shared-nothing: no
    composition expressible in the model hands one component a reference to
    another's linear memory, which would turn "private keys never enter the
    Rocq heap" into a claim about every composition rather than an observation
    about this one. Resource integrity: handles are renumbered per instance and
    resource types are nominal to the defining component, so the service cannot
    forge a `cas` or key handle -- which is what the host's runtime allow-list
    over composed imports stands in for today. Both are statements about the
    instantiation relation, so neither waits on soundness for the whole model,
    and neither needs Iris.
  - **Iris on top, for specific adapters and compositions.** Here the fit is
    good rather than merely available: shared-nothing is an ownership property
    and falls out of framing; robust safety against an unknown adversarial
    sibling is Iris-Wasm's own contribution; `own`/`borrow` maps onto
    separation-logic ownership; and the concurrency needed for create
    exclusivity is what invariants and ghost state are for.
  The constraint that follows, worth settling before the first inductive is
  written: build the component layer on WasmCert-Rocq's store and instance
  representation, since Iris-Wasm already is, and retrofitting that later is
  painful. Check first whether its Wasm-1.0-era core coverage has what
  composition needs; multi-memory is the obvious worry. Keep the fragment
  small -- no async, streams or futures, host-owned resources only, a flat
  wiring graph -- which is all `composition.wac` uses and excludes exactly the
  part of the specification still in motion. `wac` itself needs no
  verification: what matters is the emitted artifact's semantics plus a check
  that its wiring graph is the intended one. One reservation on the Iris layer:
  the property this repo ultimately wants -- for any import behaviour
  satisfying the hypotheses, the trace satisfies the security properties -- is
  a trace property rather than a Hoare triple, and encoding the trace as ghost
  state is not where Iris is most comfortable. It earns its keep on the adapter
  specs and the capability properties; the headline theorem may be shorter as a
  direct operational argument over the step relation. Scope honestly: full
  metatheory for the fragment is person-years, while a definitional semantics
  plus the two lemmas is the part that buys the capability guarantees.
