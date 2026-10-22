# Deferred Work

- [ ] Implement rate limiting only after settling counter keying, enumeration,
  account lockout, bounded storage, trustworthy time and atomic enforcement.
  Commit `077c9be` removed the unwired `Backoff.v` policy and trace proofs;
  its parent retains the model for reference. Any replacement must connect its
  bounds to actual request handling, including concurrent requests and resets.
- [ ] Preserve authentication-token validity across restarts by persisting the
  HMAC signing key, rather than generating a new one on every host startup.
  Create it atomically on first run with narrowly scoped filesystem access and
  restrictive permissions; concurrent starts must use the same winning key.
  Persist the key, not individual JWTs. Keep key rotation and expiry explicit.
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
- [ ] Extract `authentikate:config/service` and `authentikate:config/policy` into
  a config component, with the HMAC key generated atomically into persistent
  storage from `wasi:random` on first run. This is separate from the completed
  storage extraction: the signing key remains ephemeral and the custom config
  imports still require the host. Wasmtime 50's `serve -S cli` enables the full
  WASI linker and honors `--dir` preopens, so the target is
  `wasmtime serve -S cli --dir <storage>::/accounts ...` once config is composed.
  The custom accounts interface is already resolved inside the composition;
  no runtime keyvalue provider or atomics draft is needed.
  Rejected alternative: `atomics.increment` on a per-email claim counter plus
  `set` preserves one winner but separates the claim from writing the record.
  A crash leaves a permanently claimed, empty account, and failed attempts grow
  attacker-controlled counters. Unlike a temporary record published by hard link,
  a counter has nowhere to put the value before claiming it.
- [ ] Bring routing and the Host/Origin policy under proof in a separate Rocq
  HTTP component, rather than widening the authentication service's `handle`.
  Today `components/gateway` makes those decisions in ordinary Rust --
  unit-tested natively, but unproved -- and serves constant static assets.
  The new component would import `authentikate:service/api` and
  `authentikate:config/policy`, but not signing configuration; the service's
  body-only API and authentication proofs stay unchanged. Give it the method,
  request target, authority and relevant header values (preserving duplicate
  Origins), and return headers alongside status and body. Keep streaming,
  deadlines and body-size enforcement in the gateway, with a proved preflight
  decision so forbidden requests and asset routes need no body read. Route
  gateway-generated errors, including timeouts and oversized bodies, through
  the proved response finalizer too. Candidate theorems: authentication
  operations are invoked only for `POST` on their matching API routes;
  disallowed authorities and foreign or duplicate Origins are rejected before
  authentication; every finalized response has the security headers; accepted
  asset routes return fixed bytes, with an empty body for `HEAD`. The new
  component needs its own hand-written, unproved lowering glue, rather than
  expanding `components/service/adapters/service.wat`. The gateway must still
  faithfully pass metadata, obey preflight decisions and emit returned headers:
  this isolates and potentially shrinks the trust gap, not closes it outright.

- [ ] Reduce the gateway's vendored WIT further. Splitting `world service` out
  of `api.wit` took `components/gateway/wit/deps` from fifteen files to eight
  by removing the keyvalue, email, wall-clock and `wasi:random` packages,
  which were present only because a world the gateway never instantiates
  named them -- and with `wasi:clocks@0.2.0` gone there is one clocks version
  again, so the `wasi::clocks0_2_4` workaround is retired. What remains is the
  pinned `wasi:http`/`wasi:io`/`wasi:clocks` set plus `authentikate:config`
  and `api.wit`, copied because `wit_bindgen::generate!` needs a literal path
  and cannot stage sources the way `host/build.rs` does. `make check-wit`
  fails on drift in the two that have an authoritative source elsewhere,
  which is a guard rather than a fix.

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
  wires the service to the Argon2, HMAC-SHA-256 and stdout-email components -- so
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
