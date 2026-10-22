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
  `wasi:filesystem`'s `open-at` with `create | exclusive` is `O_CREAT|O_EXCL`,
  which is create-if-absent atomically at the OS level, so it discharges
  `store_creates`'s exclusivity across processes rather than within one host --
  a stronger basis for `signup_happens_once` than the current mutex. The
  service never overwrites a record, so only the `seen = None` case of `swap`
  needs implementing; the rest can refuse. One correction to make before
  writing it: `create | exclusive` on the final path claims the *name*
  atomically but not the contents, since the bytes go in afterwards, which
  reopens exactly the claim-then-write window that disqualifies the
  `increment` route below. The fix is the standard one -- write the whole
  record into a uniquely named temporary (`wasi:random` for the name), then
  `link-at` it to the account path, which fails with `exist` if the address is
  taken. `link-at` is the atomic claim *and* the content is already there when
  it succeeds, so `create_then_get` and `create_is_exclusive` are discharged
  by one syscall and a failed claim leaves no trace. That is also the
  structural reason `increment` cannot be fixed the same way: a counter has
  nowhere to put the record, so its claim is separable by construction.
  Note that key-to-path encoding becomes attacker-facing surface -- email
  addresses contain `/`, `.` and case, and path length is bounded -- so the
  path should be a hash of the key rather than the key.
  `wasi:filesystem` is not in the `wasi:http/proxy` world, so the question was
  whether `wasmtime serve` can supply it at all. It can: wasmtime 50's
  `serve.rs` repurposes `-S cli` as "enable all WASI interfaces instead of
  just those in the proxy world" (`add_wasmtime_wasi_to_linker`, then only the
  HTTP interfaces on top), and `serve` shares `RunCommon::configure_wasip2`,
  so `--dir` preopens apply. `wasmtime serve -S cli --dir ...` is the target
  invocation. Doing this plus folding
  `authentikate:gateway/settings` into a config component (with the signing
  seed generated into that same directory from `wasi:random` on first run,
  rather than baked in at build time) would leave `wasi:filesystem` as the only
  non-proxy import and delete the host rather than shrink it.
  - Rejected alternative, recorded because it is non-obvious enough to be
    reinvented: build create-if-absent out of `wasi:keyvalue/atomics.increment`
    by incrementing a per-email claim key and treating a returned `1` as
    winning the race. It is a correct atomic test-and-set and exactly one
    caller ever sees `1`, so create-at-most-once survives. What does not is the
    atomicity of claim and write: with `cas`/`swap` the record *is* what is
    written atomically, while claim-then-`set` has a window in which the key is
    taken and no account exists, so a crash or a refused write leaves the
    address permanently unclaimable and unrecoverable without leases. Failed
    attempts also increment, making the counter attacker-driven storage growth,
    and wasmtime's draft is `delta: u64 -> result<u64>` against this repo's
    `i64 -> i64`, so adopting it means editing `service.wit` and the
    attacker-facing `store.wat`. This matters because it is the only route to
    plain `wasmtime serve`: that subcommand does link `wasi-keyvalue` and
    `wasi-config` providers behind `-S`, but its vendored `atomics` is an
    earlier draft with `increment` alone and no `cas` resource at all, so the
    composed artifact cannot link against it as written.
- [ ] Bring routing and the Host/Origin policy under proof by widening the Rocq
  `handle`: take a method, a path and the headers it depends on, and return
  headers alongside the status and body. Today `components/gateway` makes
  those decisions in ordinary Rust -- unit-tested natively, but unproved -- and
  the static assets are constants it serves itself. Candidate theorems:
  only `POST` reaches `handle`, a foreign `Origin` is always refused, the
  security headers are on every response, and the asset routes are constant.
  The cost is that the `.wat` dispatch glue in
  `components/service/adapters/service.wat` grows, because `config` and the
  request record both have to be lowered; that glue is hand-written and
  unproved, so this trades a Rust-sized gap for a smaller Wasm-sized one rather
  than closing it outright.

- [ ] Take the Ed25519 handle out of `api.config` so the gateway stops seeing
  the signing seed. Its only non-service imports are three calls in
  `service_config` -- `ed25519.import-key`, `ed25519.public-key` and
  `argon2.recommended-params` -- none of them on the request path, and all
  three exist because `config` is expressed as `key: u32` plus `pubkey` and
  `dummy-params` rather than as the seed. The service's own world already
  imports `authentikate:crypto/ed25519@0.1.0`, so its adapter can import the
  key itself: `settings` would hand the seed straight to the host-facing edge
  of the service, the gateway would drop both crypto imports and its
  `signing-seed` field, and the capability story would match what
  `gateway.wit` claims. Cost is glue in
  `components/service/adapters/service.wat`. Keeping `config`'s `key: u32` and
  having the adapter fill it leaves the Rocq side and `Proofs.v` untouched;
  only changing `cfg_key`'s shape propagates into the proofs.

- [ ] Reduce the gateway's vendored WIT. `components/gateway/wit/deps`
  carries copies of `service.wit`, the crypto and email interfaces and the
  keyvalue draft because `wit_bindgen::generate!` needs a literal path and
  cannot stage sources the way `host/build.rs` does. `make check-wit` fails on
  drift, which is a guard rather than a fix. Two versions of `wasi:clocks`
  coexist there as a result -- the service's `wall-clock@0.2.0` and
  `wasi:http`'s `monotonic-clock@0.2.4` -- which is why the gateway refers to
  `wasi::clocks0_2_4`.

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
