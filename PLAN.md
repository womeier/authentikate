# Authentikate — plan

A small authentication backend whose request handling is written in Rocq,
compiled to WebAssembly by CertiRocq, and run under a Rust Wasmtime host. Cryptography is
not written in Rocq: registered primitives call custom component interfaces.
Separately buildable Rust providers implement these interfaces; WAC composes
them directly with the service and stdout email component for the web demo.

The original goal was a constant-time service. That remains an unresolved
security goal, not an established property of this implementation. See
[Constant time](#constant-time).

This is a working draft, updated to the repository state after `7c208f8`,
including the integrated signup service and web demo. Design rationale below
is retained where useful; completed mechanisms are distinguished from goals.

## Current state

| Area | Current status |
| --- | --- |
| Rocq service | Signup, login and validate compile through `components/service/theories/extraction.v`, included in `components/service/_RocqProject` |
| Default Nix build | Checks proofs and adapter/runtime tests; installs core and component Wasm artifacts |
| Bytes/base64 | MetaRocq bytestrings; local upstream instance and strict unpadded rocq-base64 `ByteString` wrapper, pinned at `b0f629e5` |
| Foreign calls | Seven registered primitives, void/global-result ABI, force-argument workaround for CertiRocq `6d34b50b` |
| Component | Custom service WIT export; custom crypto and standard WASI keyvalue imports remain unresolved providers |
| Rust providers | `make crypto-components`; `make host-component` builds/composes them with the service and stdout email using WAC; not Nix packages |
| Web demo | Rust Axum/Wasmtime host (`cargo run`), actual composed crypto/email, in-memory WASI keyvalue, fresh composition per request |
| CI | Workflow builds/tests components, composes Rust providers, runs Rust HTTP tests and uploads Wasm artifacts; remote result not yet verified |
| Verification | Structural proofs and tests exist; `login_then_validate` is proved and `Print Assumptions` reports it closed; no whole-service unforgeability or timing proof |
| Still missing | Atomic creation, connected backoff, OpenAPI/client generation, timing tests and production hardening |

Commands from the repository root:

```sh
nix build
nix develop --command make -C components/service
nix develop --command make -C components/service test
nix develop --command make crypto-components
make host-component
cargo test --locked
cargo run --locked
cargo test --locked -p authentikate-argon2 -p authentikate-ed25519
```

The Nix development shell provides a locked Fenix Rust toolchain with the
`wasm32-unknown-unknown` standard library; no rustup setup is needed. The host needs
Rust >=1.97 and `build/host.component.wasm`. WAC 0.12.0 is included in the Nix
development shell. `make compose-host` composes existing
service/provider artifacts without rebuilding Rocq; `make host-component` builds
all four first. Node remains only build/test tooling, not a running server.
`nix build` still installs the uncomposed service artifacts under `result/`.

## The service

Three operations, JSON in and JSON out. The component exports
`authentikate:service/api@0.1.0` (`components/service/wit/service.wit`), not WASI HTTP: each
operation takes config, Unix time and request bytes and returns status/body.
The Rust demo exposes the following HTTP routes:

| Method | Path            | Request                        | Response                     |
| ------ | --------------- | ------------------------------ | ---------------------------- |
| `POST` | `/api/signup`   | `{ email, password }`          | `201 {}` on acknowledged creation |
| `POST` | `/api/login`    | `{ email, password }`          | `{ token }` (a JWT)          |
| `POST` | `/api/validate` | `{ token }`                    | `{ valid, claims? }`         |

- `signup` returns `409` for any existing key, including a corrupt record.
  It validates enrollment JSON before writing; only `Some true` from the
  write yields `201`. Get/enroll/record/write failures yield `500`.
- `login` looks the user up, checks the password against a stored hash, and
  on success mints a JWT.  Wrong credentials: `401`, no detail about which
  half was wrong. No timing equivalence is established. Store refusal and
  signing failure can return `500` instead.
- `validate` verifies the token's signature, issuer and freshness, and reports
  whether it is good.  A bad token is a `200` with `valid: false` rather than
  an error — it is a question, not a failure.

JWT shape: compact JWS, `EdDSA`/Ed25519.  The earlier plan started at `HS256`
on the grounds that one symmetric key is the simplest thing that can be made
to work; that is no longer the shorter path, since the Ed25519 component
already exists and HMAC-SHA256 does not.  Claims: `sub`, `iat`, `exp`, and an
`iss` naming the service.

The algorithm is **not** read from the token header to select a verifier.  It
is fixed at EdDSA in the code, which makes "a token claiming `alg: none` or
`HS256` is rejected" true by construction rather than by a check that can be
got wrong.  This is the classic JWS break and it should cost nothing to be
immune to it.

## Layers

```
   HTTP /api/* -> host/src/main.rs -> Wasmtime -> host.component.wasm (WAC)
                              ┌───────────────────────────────────────┐
                              │  Rocq core module (CertiRocq)         │
                              │   routing, base64url, JSON, JWT,      │
                              │   claim checks, record decoding —      │
                              │   every decision                      │
                              │          │ registered primitives      │
                              │  components/service/adapters/         │
                              │    argon2.wat, ed25519.wat             │
                              │    store.wat                          │
                              │    service.wat                        │
                              └──────────┬────────────────────────────┘
                                         │ canonical ABI
                 +----------------+----------------+
                 | custom crypto imports           | WASI keyvalue import
                 v                                 v
   WAC connects Rust Argon2 + Ed25519 components    in-memory Rust map
   and stdout email directly to the service.       (WASI keyvalue resource)
     Argon2 -> WASI random (fresh enrollment salts)
     Ed25519 -> instance-local keys, host import-key provisioning
     stdout email -> WASI stdout/I/O
```

The split: everything that is a decision lives in Rocq, everything that is a
primitive lives in a provider. Rust provides transport, storage, clock, entropy,
stdout and configuration, but no service crypto interfaces or forwarding. Note
which side the stored record's *format* falls on — Rocq's, because
`wasi:keyvalue` moves opaque bytes and `Store.decode` is what interprets
them.  That is the main reason to prefer a blob store here over SQL columns:
with SQL, the schema and the decoding both sit outside the verified
perimeter. The timing design aims to keep secret operations behind the crypto
boundary; this is not a proof that the whole service is constant-time.

### Rocq (`components/service/theories/`)

- `Bytes.v` — `bytes := MetaRocq.Utils.bytestring.String.t`, byte helpers and
  encoding arithmetic. This is not the earlier `list byte` API.
- `Base64.v` — the MetaRocq bytestring instance, strict unpadded wrappers over
  rocq-base64's `ByteString.encode/decode url_unpadded`, and correctness proofs.
  The flake pins rocq-base64 `b0f629e5`, which no longer depends on MetaRocq.
- `Json.v` — enough JSON to read a two-field request object and write a
  response (including nested claims). A parser on bytes, total, returning an option. Only a
  canonical printer, so the round-trip proof does not need a general one.
  `JsonProofs.v` has the round trip: `parse (print (JObj fs)) = Some (JObj fs)`
  for flat objects, axiom-free, under string well-formedness, fresh keys,
  fewer than 15 fields and numeric values below `10^32`. It is not a general
  round trip for arbitrary bytes or nested objects.
- `Claims.v` — `exp`/`iat` checks against a clock the host supplies, on `N`.
- `Jwt.v` — the compact JWS: split on `.`, decode the halves, check the
  header, hand the signing input to the crypto operations.
- `Crypto.v` — the FFI surface, as a **record of operations** rather than as
  axioms:

  ```coq
  Record argon2_params := MkParams {
    ap_algorithm : N; ap_memory_kib : N; ap_iterations : N;
    ap_parallelism : N; ap_tag_length : N
  }.

  Record crypto_ops := MkOps {
    argon2_verify  : Secret.t -> bytes -> argon2_params -> Secret.t -> option bool;
    argon2_enroll  : Secret.t -> option bytes;               (* public JSON *)
    ed25519_sign   : Key.t -> bytes -> option bytes;         (* key handle, msg *)
    ed25519_verify : bytes -> bytes -> bytes -> option bool  (* pk, msg, sig *)
  }.
  ```

  The cost parameters are an argument rather than a constant in the adapter,
  and all of them are public: how expensive a hash was is not a secret, and
  it *cannot* be one, because a tag is only verifiable under the parameters it
  was derived with — so they are stored beside the tag.  Reading
  `recommended-params` inside the adapter, as the first version did, binds
  every stored tag to whatever that returned the day it was written, and
  invalidates all of them at once the next time the recommendation moves.
  `N`, not `nat`: 19456 as a unary `nat` is 19456 heap cells to walk per
  login.

  Three reasons for a record and not bare `Axiom`s. It lets the pure service
  be written and proved independently of the extraction boundary.
  It turns the trust boundary into *hypotheses* — every theorem names what it
  needs, which is a stronger and more honest statement than an axiom nobody
  reads.  And `option` in the results forces the Rocq side to handle a
  component that answered `error`.

  The record is instantiated once, in `extraction.v`, with the registered
  primitives.  Nothing above `Crypto.v` changes when that happens.
- `Secret` and `Key` — opaque types, sealed module signatures, living in
  `Crypto.v` beside the operations that consume them.  `Secret.t` has no
  eliminator, no equality and no way back to `bytes`, so nothing above it
  *can* inspect an already sealed value. This is a source-level abstraction
  discipline, not a timing theorem for parsing, providers or the service. `Key.t` is a
  handle to the signing key rather than its bytes.  CertiCoq erases the
  module structure, so neither costs anything at runtime.
- `Store.v` — the stored record and the lookup.  See
  [Persistence](#persistence); the shape is a `store_ops` record carrying
  `kv_get : bytes -> option (option bytes)` and
  `kv_set : bytes -> bytes -> option bool`, a `user` record, a `decode` for
  the stored JSON, and `stored : store_ops -> bytes -> lookup_result` with
  `lookup_result` = `Found`/`Absent`/`Unavailable`. `enrollment_record` adds
  the email to public enrollment JSON and decodes the result before writing.
- `Api.v` — `handle : crypto_ops -> store_ops -> config -> N -> route ->
  bytes -> response`.  This is the whole service.  The clock is an
  argument, not an import: it keeps `handle` pure and makes the `exp` proofs
  trivial.  `config` carries what the host installs — the key handle, the
  public key, the issuer, the TTL, and the dummy salt, tag and params that
  rule 3 below needs.  The credential check is factored out as `login_check`,
  because the found and not-found cases having one code path is the whole of
  rule 3 and deserves to be readable on its own.
- `Backoff.v` — exponential backoff as a policy: `delay`, `throttled`,
  `on_failure`, and a `failures` count over a trace of timestamped attempts.
  Proved, and **not wired into `handle`**; see [Rate limiting](#rate-limiting).
- `Proofs.v` — what is actually established (see below).
- `extraction.v` — the service extraction: eight registered primitives and
  signup/login/validate, compiled by the default build through `components/service/_RocqProject`.

Use `N`, not `nat`, for timestamps and lengths.  CertiCoq represents `nat` in
unary, so an `exp` around 1.8e9 would be 1.8e9 heap cells.

### The FFI (`components/service/adapters/`)

The mechanism is `CertiRocq Register`, not unregistered axioms. The earlier
upstream backend gap is resolved by the fork pinned at `6d34b50b` in
`flake.nix`; the real service now compiles. Seven registrations cover Argon2
verify/enroll, Ed25519 sign/verify, keyvalue get/set and `Secret.of_bytes`.

These imports return **void**, publishing the Rocq result through the shared
mutable `result` global, with shared memory/allocation globals. The pinned
compiler's constant forcing adds a leading dummy argument before the real
Rocq arguments. Explicit registration arities count it and adapters ignore it;
without this workaround imports can be called too early with shifted arguments.

Three adapters (`components/service/adapters/argon2.wat`, `components/service/adapters/ed25519.wat`,
`components/service/adapters/store.wat`) bridge heap values to canonical ABI. `components/service/adapters/service.wat`
provides canonical signup/login/validate wrappers, config/clock marshalling,
curried closure calls and response lowering. Its seven FFI boundary wrappers
restore four-byte heap alignment after byte-oriented foreign allocations,
including error paths returning immediate `None`.

`components/service/build.mjs` merges the extracted core, adapters and runtime
with `wasm-merge`, removes link-only exports and unused builtins (checking
they are unreferenced), prunes with `wasm-opt`, embeds authoritative WIT and
runs `wasm-tools component new` and validation. The output still imports
custom `authentikate:crypto/{argon2,ed25519}@0.1.0` and standard
`wasi:keyvalue/store@0.2.0-draft`. `make host-component` then uses the explicit
`host/composition.wac` graph to connect the Rust crypto and stdout email components.
The default `make`/Nix artifact remains the independently reusable service.

The internal `wasm-merge` step is deliberately retained for now, separately from
the implemented component-level provider composition. Deferred removal and
CertiRocq work are tracked in [TODO.md](TODO.md).

The value representation, probed from the backend's own output rather than
assumed:

| Value | Representation |
| ----- | -------------- |
| `BS.EmptyString` | immediate `1` |
| `BS.String h t` | pointer to `[tag=0 @0, h @4, t @8]` |
| byte `v` | immediate `2v+1` |
| `false` / `true` | immediate `1` / `3` |
| `None` / `Some x` | immediate `1` / pointer to `[tag=0 @0, x @4]` |
| closure | `[tag @0, func_idx @4, env @8]`, env `1` when closed |
| compiled function | `(param env i32) (param arg i32)`, result into the `result` global |

One trap worth recording: foreign byte results can exceed generated heap
headroom. A bytestring costs 12 bytes per nonempty cell, so adapters grow
memory themselves rather than trusting it; the runtime restores alignment.

`components/service/theories/extraction.v` is compiled in `components/service/_RocqProject`. Two design details
remain worth recording:

- The `Register` vernacular itself is fine today — it is the plugin's own
  mechanism, used by `CertiRocq/Plugin/GMP.v` and friends — and the syntax
  requires an `Include` clause even when there is nothing to include, so a
  Wasm build writes `Include [ ]`.
- The sealed secret and extraction pull against each other.  `Module Secret :
  SECRET` is opaque *to erasure as well*, so `Secret.of_bytes` arrives at the
  backend as an axiom, and `parse_request` calls it on every login.  The fix
  that keeps the seal is to register it too, as a foreign identity
  (publish the real argument in `result`, ignoring the force dummy); the fix
  that loses it is transparent ascription (`<:`),
  after which any caller can unfold `Secret.t` to `bytes` and match on a
  password.  We register.  `Key.of_handle` needs none of this: the host builds
  `cfg_key` and the extracted code only passes it along.

### Rust host (`host/`, assets in `host/assets/`)

`cargo run` loads `build/host.component.wasm`, composed with WAC from the service,
Rust Argon2, Rust Ed25519 and stdout email components. No host-provided crypto
interfaces exist. The same signer/hash instances wired into the service are
re-exported for seed provisioning, public-key derivation and dummy hashing.
Bindings stage the authoritative WIT sources instead of copying crypto types.

Each request gets a fresh composition to reclaim all Wasm heaps. An ephemeral
host seed survives requests and is reimported into each signer; the host map
preserves account records. One blocking worker executes component requests at
a time, with bounded admission (eight including the active request). This
serializes get-then-set in one process only. Fuel and Wasm memory limits bound
guest execution; they are not a production resource policy or timing theorem.

The host provides WASI clock/random/stdout and keyvalue resources, but no guest
filesystem, environment or network access. It enforces strict Host/Origin policy,
JSON content type, a 16 KiB streaming limit and a body read deadline. Loopback is
the default; explicit `LISTEN`/`PUBLIC_ORIGIN` support controlled proxy tests.
Accounts and keys vanish on restart. See `host/README.md` for commands and limits.

### Rust crypto (`components/crypto/`)

Two components, each exporting one interface of the `authentikate:crypto@0.1.0`
package:

- `components/crypto/wit/argon2.wit`, `components/crypto/argon2/` — Argon2 on RustCrypto's `argon2`,
  with `subtle` for the constant-time tag comparison.  Exposes `derive`,
  `verify`, `enroll` and `recommended-params`; no PHC strings or clock.
  Enrollment imports `wasi:random/random@0.2.0`, requests 16 fresh bytes and
  returns public JSON with base64url salt/tag and numeric algorithm/cost fields.
  Salt generation stays outside Rocq; the public salt is stored and passed
  through Rocq, not kept secret.
- `components/crypto/wit/ed25519.wit`, `components/crypto/ed25519/` — Ed25519 on `libcrux-ed25519`.
  Exposes host provisioning via `import-key`, plus `public-key`, `sign` and
  `verify`, the last of them strict in the
  RFC 8032 sense. Checked against the RFC 8032 §7.1 vectors. Private keys
  remain in the provider instance's bounded key table; Rocq receives opaque
  u32 handles, never private-key bytes. Handles die with the instance, so a
  fresh Rust provider instance must be provisioned again. This provider
  imports no randomness or I/O; importing a key is stateful.

`make crypto-components` builds/componentizes both crates separately. They
are neither flake packages nor included/composed by `nix build`.

Ed25519 uses libcrux; Argon2 remains on RustCrypto because libcrux has no Argon2.
The Ed25519 wrapper rejects small-order public keys and R points in addition to
libcrux's canonical-encoding and signature checks. Wrong-length inputs return
errors; invalid point encodings return `false`. Private seeds use zeroizing
buffers, but libcrux 0.0.10 does not explicitly wipe internal expanded-key
temporaries; this does not provide full secret erasure. The WIT function
signatures and `Crypto.v` assumptions are unchanged.
Libcrux's guarantees must be scoped to the selected algorithm and implementation,
not transferred to the wrapper, Wasm toolchain, or whole service by name.

## Persistence

`wasi:keyvalue`, not SQL. The key is the email and the value is a JSON object.
Rocq decides authentication and record interpretation; the host/provider
remains trusted for storage behavior and durability.

Why not SQL.  A query is a *decision*, so by the rule above it belongs in
Rocq — but getting it there means either building a query string in Rocq (a
string the host then interprets, which puts the decision back outside) or
formalising SQL.  `~/Documents/rocq-sql` (Benzaken–Contejean,
`SQLFormalSemantics`) does the latter properly, and is the wrong tool here
anyway: 43k lines of dependency, CC-BY-NC-ND licensed, no query *printer* —
it evaluates queries against bags rather than emitting SQL — and every
feature it models is one this lookup does not use.  `wasi:sql` is a
non-starter for a different reason: it is phase-one draft with no wasmtime
implementation.

So: a `get` by primary key for login, and `get` followed by `set` for signup.

```
key    the email, verbatim, as a UTF-8 string
value  {"email": …, "salt": <b64url>, "tag": <b64url>,
        "algorithm": n, "memory_kib": n, "iterations": n,
        "parallelism": n, "tag_length": n}
```

Decisions worth recording:

- **`option (option bytes)`, not `option bytes`.**  `None` is the store
  refusing and becomes a 500; `Some None` is the key being absent and, on
  login, becomes the dummy-hash path and a 401 (on signup it permits enrollment).
  Collapsing them would let a store outage
  read as "no such user" on every account simultaneously — the same mistake
  `argon2_verify`'s `option bool` exists to avoid.
- **The record is decoded in Rocq**, as `Store.decode`, so the format is
  inside the verified perimeter and the adapter stays a byte-mover.
- **Base64url for the binary fields**, because it is the encoding that
  already has a proved round trip.  JSON for the record, because the parser
  is already here and is strict: a duplicate key in a stored record is a
  rejection, not an interpretation.
- **`u32` bounds on the five cost knobs**, checked by `Store.of_json`.  The
  canonical ABI would silently truncate a wider one, and hashing under a cost
  nobody wrote down is worse than refusing.
- **On login, corrupt and foreign records answer `Absent`**, the same as a missing key:
  a 500 for an unparseable record would be a statement that the account
  exists.  The cost is diagnosability — a deployment that breaks the record
  format locks every user out with "wrong password" — and the mitigation is a
  smoke test, since this module cannot log.
- **Enrollment writes public JSON, not a serialized `Secret.t`.** The seal
  is one-way; the provider explicitly returns public salt/tag text and
  `Store.enrollment_record` adds the email and validates the final record.
  `ffi_kv_set` now exists and returns an inspected `option bool`, not `unit`:
  a unit-valued write risks erasure as definitionally `tt`. The acknowledgment
  keeps this call live, but does not establish atomicity or temporal semantics.
- **Signup checks the raw key**, not `Store.stored`: even corrupt or foreign
  existing values conflict with `409` and must not be overwritten sequentially.
  Get-then-set still races with concurrent writers; standard `bucket.set` is
  not create-only. A transactional store or external serialization is needed.
- **`validate` reads no key at all**, since a token carries its own claims
  and signature.  Validation therefore keeps working while the store is down
  — and revocation is, for the same reason, not expressible.

Why `store_ops` and not a sealed `Module M : MAP` with `Parameter get`
registered like `Secret.of_bytes`.  Mechanically the module version works and
extracts identically.  But `get` would then be a *function* in the logic: two
reads of one key would provably agree, licensing common-subexpression
elimination across reads the real store is free to answer differently, and
every theorem downstream would name the axiom.  The record keeps `Proofs.v`
closed under the global context and confines the fiction to `extraction.v`,
which proves nothing. The pure operation records still do not model mutable
state over time: they prove no read-after-write or concurrency guarantee.
What the structural theorems say is "whatever the store
returned, it decoded, named this email, and verified" — true of the running
system.  What no design can say is that the store returned the record that
was written for that email.

The adapter, `components/service/adapters/store.wat`, has one wrinkle worth knowing: keys are
`string` in `wasi:keyvalue`, so the canonical ABI *traps* on a key that is
not well-formed UTF-8, and the email in a login body is attacker-controlled.
It therefore validates per RFC 3629 — rejecting overlongs, surrogates and
anything above U+10FFFF — and answers `Some None` for a key that fails, which
is honest: every key this service writes went through the same path, so a
non-UTF-8 key names no account. The current default adapter suite exercises
invalid UTF-8 get/set behavior; the existing `tests/run.sh` helper also checks
the validator against Node's decoder, but is not the default Nix test driver.

## Rate limiting

Proved in `Backoff.v`, axiom-free, and deliberately not connected to
`Api.handle`.

Two theorems, and the pair is the point:

```coq
guesses_are_logarithmic      (* T <= base*(2^n - 1)  =>  at most n guesses *)
guesses_are_linear_past_cap  (* T <= n*cap           =>  at most n guesses *)
```

`failures` counts attempts that reach the credential check, by induction over
a trace of timestamps; a throttled attempt costs the attacker no guess and the
service no Argon2.  Read the first backwards, which is how it gets used: to buy
`n` guesses an attacker must hold the address for `base*(2^n - 1)` — about
1000x base for ten, 10^6 for twenty.

**But the second governs in practice.**  Once the cap binds the bound is
linear, and the point of a cap is that counters reach it — so `bo_cap`, not
`bo_base`, sets the long-run guess rate.  Backoff buys a sharp transient and
then settles at one guess per cap, forever.  Tuning the base and leaving the
cap at a minute is choosing one guess per minute.  Also: `bo_base = 0` is not
"backoff off", it is "both theorems hold vacuously".

Three reasons it is not wired in, two of them adversarial to properties
already proved:

- **Keying.**  Keyed on the email, a distinguishable 429 is a user-enumeration
  oracle easier to exploit than the timing channel rule 3 below aims to reduce: a status code
  rather than a microsecond.  Preserving rule 3 means counters for emails that
  do not exist, which is an attacker-driven unbounded write.  Keyed on the
  client address there is no per-account leak, but the address comes from the
  host, outside the perimeter.
- **Lockout.**  Keyed on the email, anyone who knows an address can hold its
  owner out by failing logins.  A cap bounds the damage per attempt, not a loop.
- **The clock is security-critical.** Token issuance and freshness already
  trust host time; backoff would additionally need monotone time and an
  explicit policy for clock jumps, or a host can bypass throttling.

And one mechanical blocker: the read-modify-write must be atomic or the bound
is vacuous — n concurrent requests all read the same count.
`wasi:keyvalue/atomics` has `increment` and `cas`; a plain get-then-set does not.

## Account creation

Built as `RtSignup`, exported through WIT and `/api/signup`. The implementation
chooses an inspected `ffi_kv_set` acknowledgment instead of the earlier
write-at-edge proposal. The pure `store_ops` abstraction keeps structural
proofs quantified over operations; only extraction registers the effects.
This does not give those effects a temporal or transactional proof.

The sequence is raw `kv_get`, reject any existing value, enroll, validate and
add email in Rocq, then set. Only `Some true` acknowledges creation (`201 {}`);
`None` and `Some false` are `500`, as are enrollment or record validation
failure. `created_requires_persistence` proves this structural implication,
not future durability or uniqueness. `components/service/theories/SignupTests.v`
covers refusals and
corrupt/mismatched existing records as well as success.

Atomic create-if-absent remains unimplemented. The synchronous single-process
demo serializes calls and tests concurrent duplicates as 201/409, but that
does not fix the get-then-set race for asynchronous or multi-process stores.
The earlier write-intent/threaded-state design remains an alternative if a
stronger effect model is needed. Generic `Store.encode` of an opaque user and
a corresponding decode/encode theorem have not been added.

Two things that bite, both non-obvious:

- **Encoding an opaque tag would break the `Secret.t` seal.** Writing a record means
  base64-ing the tag, which means reading it, and base64 encoding branches on the
  value, so encoding secret bytes in Rocq would add value-dependent branches.
  The implemented solution is for the Argon2 provider to return the tag already
  base64url-encoded, so Rocq only handles public text.  That keeps the seal
  rather than carving an exception into it.
- **Registration leaks existence by construction.**  "Email taken" is an
  enumeration oracle. The current `409` deliberately discloses existence,
  including the presence of corrupt keys. A future confirmation-mail flow
  could always return 202 and tell the truth only by email; it is not built.

## Constant time

No whole-service constant-time property is established. Extracted Rocq has
value-dependent branches, pointer-chased bytestrings and allocation; the
compiler's functional correctness is not a timing theorem. The source-level
seal prevents inspecting values *after* they become `Secret.t`, but parsing
password bytes, decoding stored tags, provider code, storage and the runtime
remain outside that limited discipline.

The architectural goal is to move already sealed secrets without inspecting
them and put crypto behind provider interfaces. Passwords and private keys
are secret; enrollment explicitly treats encoded salt/tag records as public
output (still sensitive password-verifier data for storage/access control).
JWT contents are not confidential, but bearer tokens must not be logged or
disclosed. Public salts enter Rocq; fresh salt generation and raw private keys
do not. This boundary is not evidence of timing equivalence.

The rules that follow:

1. `Secret` in `Crypto.v` makes post-sealing opacity structural, not the
   entire request path constant-time.
2. Password-tag comparison and signature verification stay in the provider,
   not Rocq's short-circuiting byte equality. Signatures do return to Rocq
   for token encoding, and enrollment returns public encoded salt/tag JSON.
   Private keys never return; signing uses only a handle.
3. A login for an unknown user still runs a full Argon2 against a fixed dummy
   salt, tag and parameter set, and discards the result.  Without this, the
   uniform `401` would have an obvious cheap-path timing distinction.
   This mitigates one channel; it does not prove equal timings.
   `Api.login_check` is the one function where this matters, which is why it
   is one function.

   Per-record cost parameters put a limit on how well this works, and it is
   worth being exact about it.  The dummy hashes under `cfg_dummy_params`,
   one parameter set; a deployment whose records span two generations of
   `recommended-params` has logins of two different durations, so a login's
   duration reveals which generation an account belongs to, and accounts
   stored under a retired recommendation become distinguishable from absent
   ones.  The fix is a migration that re-hashes on login — which needs a
   migration path beyond the existing signup write — not a cleverer dummy.
   Re-hash-on-login is not implemented. Until then: migrate all records at
   once, and move `cfg_dummy_params` with them.
4. **Argon2id is not constant-time, by design.**  Per RFC 9106 its addressing
   is data-independent for only the first half pass and data-dependent after,
   so its memory access pattern depends on the password.  See the open
   question below; enrollment currently selects Argon2id in both providers.

What is not covered, stated plainly rather than left to be discovered:

- The JSON parser runs over the password before it can become opaque, and
  must branch to find the closing quote.  It therefore leaks the password's
  **length** and content-dependent parsing/rejection behavior (the parser
  rejects escapes). There is no analysis proving that these are the only
  observable channels. A concrete leakage policy and threat model are still
  needed rather than treating attacker-supplied passwords as public.
- **The engine is not under our control.**  An optimising JIT, whether
  wasmtime's or Node's, may introduce timing behaviour that no property of
  the module predicts. Neither generated-code nor runtime-level timing
  guarantees have been proved here.
- Replay and revocation.  These are bearer tokens with an `exp` and nothing
  else.

For future evidence rather than argument: `dudect`-style statistical timing
tests are planned but **not implemented**, for either Rust crate or the demo.
Functional tests do not substitute for them. If a machine-checked Wasm-level
property is ever wanted, the prior art is CT-Wasm (Watt et al., POPL 2019),
which adds secret types and a type system rejecting secret-dependent branches
and memory indices.  CertiCoq-Wasm emits nothing compatible with it today,
which is the reason not to aim the constant-time guarantee at the generated
module.

## Spec and client

Not implemented: there is no root `openapi.yaml`, generated `client/`, or
`gen-client` flake app. `components/service/wit/service.wit` is the current component contract;
it is not an HTTP/OpenAPI contract. The intended work remains:

- Hand-write `openapi.yaml` for all three demo HTTP endpoints and errors.
- Check in a generated client in `client/`, from `openapi-generator` (or
  `oapi-codegen`-style generation pinned in the flake so the output is
  reproducible).  Target language to pick: TypeScript is the path of least
   resistance for the existing browser frontend, independent of the Rust host.
- A `nix run .#gen-client` that regenerates it, and a check that the checked-in
  client matches what the generator produces.

## What gets proved

Worth being honest about the boundary, and about the difference between what
is proved, what is assumed, and what is merely tested.

Established without assuming cryptographic security are structural
properties over the pure operation records, not a proof of extraction,
provider correctness, storage consistency or deployment security:

1. **No token without a check.**  If `handle` answers a login with a token,
   then the lookup returned `Found u`, `u` names the email asked for, and
   `argon2_verify` returned `Some true` for that record's salt, parameters and
   tag.  The property the service exists for.  Proved, and axiom-free —
   including over the store, which is quantified rather than assumed.
2. **Algorithm pinning.**  A token whose header names anything but `EdDSA` is
   rejected.  True by construction, given the design decision above.
3. **Credential failure shape.** There is a single `unauthorized` response
   for rejected credentials: wrong password, missing key, a record
   that does not decode, and a record belonging to someone else, are
   routed together by the code; missing/corrupt/foreign-record cases have
   explicit lemmas. This is response shape, not timing equivalence. The
   theorem `unavailable_is_internal` is one-way: store refusal yields 500.
   Its converse is false: signing failure after a successful password check
   also yields `Internal`. Stale comments in `Proofs.v` must not be read as
   an established converse theorem.
4. **Expiry is honest.**  `validate` answers `valid: true` only if the
   signature check passed *and* `exp > now`.
5. **Round-trips.**  `decode (encode bs) = Some bs` for base64url, and
   `parse (print (JObj fs)) = Some (JObj fs)` for flat objects — values are
   well-formed strings, numbers or booleans, keys fresh, fewer than 15 fields,
   numbers below `10^32`. Both proved under their stated assumptions. The
   flat theorem covers candidate claims/token objects, not the nested
   validation response or arbitrary byte strings.
6. **Guess bounds under backoff.** See [Rate limiting](#rate-limiting).
   These are policy trace theorems, not bounds on this running service.
7. **Creation requires acknowledgment.** `created_requires_persistence`
   proves absent raw key, successful enrollment/record construction and
   `kv_set` returning `Some true`. It proves neither durability nor uniqueness.

Not established: forgery rejection or unforgeability. Merely assuming a
verifier is a function says nothing about which signatures it accepts.
`crypto_spec` below states sign/verify correctness, not security; tests with
tampered tokens are useful evidence, not a cryptographic theorem.

Needs a hypothesis from a `crypto_spec` bundle: that `ed25519_verify` accepts
what `ed25519_sign` produced under the matching key. A JWT sign/verify round
trip additionally needs serialization well-formedness and bounds; that full
result is not yet proved.

The statement in `Proofs.v` is proved:

```coq
Theorem login_then_validate :
  forall ops kv mail cfg now d email password body token,
    crypto_spec ops (cfg_key cfg) (cfg_pubkey cfg) ->
    ok_string (cfg_iss cfg) ->
    (now + cfg_ttl cfg < 10 ^ 32)%N ->
    parse_request RtLogin body = Login email password ->
    handle ops kv mail cfg now RtLogin body = Token token ->
    (d < cfg_ttl cfg)%N ->
    exists c,
      handle ops kv mail cfg (now + d) RtValidate
        (Json.print (JObj [(lit "token", JStr token)])) = Validity true (Some c)
      /\ c_sub c = email.
```

A token minted for an email and validated before expiry yields claims naming
that email. `Print Assumptions` reports it closed under the global context:
the cryptographic assumption travels in `crypto_spec` as a hypothesis of the
theorem rather than as an axiom of the development.

The two added hypotheses are not provable and are the host's to satisfy when
it installs the configuration. The printer does not escape, so the issuer must
be printable ASCII; the numeral round trip is bounded, so `now + ttl` must fit
in 32 decimal digits. The earlier unrestricted statement quantified over
arbitrary issuer bytes and unbounded timestamps, and admitted inputs the
serializer cannot round trip.

Beyond the lemmas that already existed, it needed parser soundness
(`parse_json_ok` and `get_str_ok`: every string `parse` returns is printable,
quote-free and backslash-free, which is also the no-injection argument),
`ok_string` closure under append and base64url so that a token can travel
inside the JSON object `validate` takes, and `claims_round_trip`, which
discharges `parse_print_obj`'s four side conditions for a claim set.

This is correctness, not security. It says tokens this service mints are
accepted; it says nothing about what is rejected. The converse — accepted
implies minted implies authenticated — needs a second `crypto_spec` field
saying that only signed messages verify, and is the next proof worth having.

`Print Assumptions login_then_validate` already runs in the proof file. That
turns "what are we actually trusting" into output rather than a comment, and
it shrinks visibly as the lemmas land.

Assumed, and not provable here: that Argon2 and Ed25519 are what their names
say, along with entropy, key provisioning, storage and runtime behavior.
Four crypto operations and two store operations are abstracted in the pure
records; the seven extraction registrations also include the secret identity.
The small explicit interface helps audit trust, but is not itself a security
proof.

## Tests and evidence

- `nix build` (also the flake build check) compiles `components/service/_RocqProject`, including
  proofs, pure signup regressions and real extraction. It then runs
  `tests/ffi-adapters.mjs` and `tests/component.mjs` before installing artifacts.
- Adapter/runtime tests cover the void/global-result ABI, ignored force
  argument, u32 handles, memory growth, all seven alignment boundaries,
  wrapper marshalling, actual extracted closures, sequential calls, failures,
  signup persistence acknowledgments and validation's storage independence.
  Crypto imports in these tests are mocks, not Rust or native cryptography.
- `cargo test --locked` uses the actual WAC-composed service and Rust Wasm
  Argon2/Ed25519/email. It checks signup/login/claims across fresh instances,
  tampering, malformed input, duplicate/concurrent signup, Host/Origin and body
  limits, real socket/chunked requests, stdout email and Linux stdout failure.
- Rust native unit tests total 14 (4 Argon2, 10 Ed25519), covering enrollment
  format/verification and RFC vectors, invalid handles/inputs and strict
  rejection cases. Native enrollment tests supply salt to the helper; they
  do not exercise WASI randomness or prove entropy quality.
- Desktop and mobile demo flows have been tested manually. This is separate
  from the HTTP suite, not an automated cross-browser or timing guarantee.
- `.github/workflows/nix.yml` runs `nix build`, uses the development shell's
  Fenix Rust and JCO tooling, composes providers, tests the Rust HTTP host, runs both Rust crypto suites and
  uploads the Wasm artifacts. Cachix is read-only for pull requests; the action
  handles pushes without a separate unconditional `cachix push`. The obsolete
  `just` commands are removed. Local workflow validation passes; no remote green
  run is claimed because `gh` is unauthenticated here.

## Open questions

- **argon2id or argon2i?**  Does the threat model include an attacker who can
  observe cache behaviour — a co-resident tenant, a local process?  If not,
  argon2id stays defensible and RFC 9106 still recommends it, since the
  data-dependent channel needs a local observer.  If the constant-time
  requirement is unconditional, it has to be argon2i, paying for weaker
  time-memory-tradeoff resistance with more iterations than
  `recommended-params` currently returns. Enrollment selects Argon2id in the
  Rust provider; changing policy needs coordinated recommendations,
  dummy parameters, records and migration, not just an adapter edit.
- **Should the signing key be a component resource?** Raw-key exposure to
  Rocq is already avoided by opaque u32 handles and a provider-owned key
  table. A WIT resource could improve lifecycle/capability semantics, but is
  not required to remove private-key bytes from the Rocq heap. Key import,
  rotation, destruction and per-instance provisioning remain design concerns.
- ~~Where do users live?~~ Answered: standard `wasi:keyvalue`, get/set by
  email; the demo supplies an ephemeral Map. Store lookup timing is provider
  behavior, not proved independent of key presence. Signup explicitly
  discloses existence; login dummy hashing does not eliminate all channels.
- **Does the bucket need a name?**  `components/service/adapters/store.wat` opens the default
  bucket with the empty identifier, because a named one needs its name as a
  pointer into linear memory and a `data` segment in the adapter would write
  at a fixed offset into the CertiRocq heap.  A named bucket wants the host
  to place the string and hand over the pointer.
- Key management: the demo generates an ephemeral key pair at startup;
  Rust providers need host `import-key` provisioning per instance. Production
  key custody, durable storage, rotation and recovery are not implemented.

## Steps

Completed foundations:

1. Nix/Rocq 9.1 toolchain, pinned CertiRocq import support and rocq-base64
   bytestring migration; default service artifacts and build checks.
2. Seven foreign registrations, three adapters and canonical runtime wrapper,
   including force-argument and heap-alignment workarounds, exercised in tests.
3. Component merge/pruning/WIT embedding; custom crypto and standard keyvalue
   imports. Optional Rust components build separately, not as Nix packages.
4. All three Rocq operations, public enrollment JSON, acknowledged writes,
   structural proofs, base64 and conditional flat JSON/decimal round trips.
5. Rust web demo with the extracted service, component-level Rust crypto/email
   composition, per-instance key provisioning and ephemeral storage; HTTP tests.
6. CI workflow aligned with component builds, HTTP/Rust tests and Wasm artifact
   upload, with pull-request-safe cache configuration and local syntax validation.

Remaining work, in priority order:

1. Prove the security direction: add a `verify_only_signed` field to
   `crypto_spec` and establish that an accepted token was minted by this
   service, and hence that some login verified a credential for its subject.
   `login_then_validate` is proved, but it is correctness only.
   Keep `Print Assumptions`; do not conflate correctness with unforgeability.
2. Define production storage/effect semantics and atomic create-if-absent;
   test concurrent writers beyond the synchronous demo. Decide whether account
   existence disclosure is acceptable or needs a confirmation-mail flow.
3. Define the threat/leakage model, choose Argon2 policy, implement timing
   measurements (`dudect`-style) and re-hash-on-login migration. No timing
   guarantee should precede evidence and a precise scope.
4. Connect backoff only after choosing keying, lockout, monotone-clock and
   atomic counter semantics; the existing policy proofs alone do not rate-limit.
5. Package the composed host/providers reproducibly in Nix. Component-level
   composition, WASI randomness and per-instance key provisioning are implemented;
   the default Nix build remains the uncomposed service. Eventually remove internal
   `wasm-merge`; keep it for now and postpone CertiRocq changes.
6. Add OpenAPI for the HTTP surface, choose/pin client generation and check
   reproducibility; no `gen-client` command exists yet.
7. Harden deployment: durable storage, key custody/rotation, TLS, recovery,
   input/cost/resource budgets, nonblocking crypto execution and operational
   observability without leaking secrets. Keep the current demo loopback-only.
8. Verify remote CI runs once authenticated;
   retain distinct proof/ABI, composed-component HTTP and Rust unit test coverage.
