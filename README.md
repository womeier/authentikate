# authentikate

An experimental authentication backend service providing the following endpoints:
- `signup`: takes an email address and password and creates an account
- `login`: takes an email address and password and returns a JWT
- `validate`: takes and validates a JWT

The backend is a single Wasm component composed of the following individual components:
- main logic: written in Rocq, compiled to a Wasm module by CertiRocq, and wrapped inside a Wasm component.
- two crypto components: password hashing with RustCrypto's `argon2` crate, HS256 token authentication with `libcrux-hmac`
- email sending component: writes the email to stdout (could be swapped with an actual implementation)
- storage component: immutable file-backed accounts, atomically published through WASI filesystem hard links


## Web Demo

Build and run the local backend demo:
Tested on linux, there is also (experimental) Apple Silicon macOS.
```sh
cachix use womeier
nix run .#authentikate-local
# visit localhost:3000 in the browser
```
On macOS, the Wasm component is fetched from `womeier.cachix.org`,
only the Rust web host is compiled locally. It is not tested.
On Linux, the cache is optional and missing components can build locally.


## Wasm Component Interfaces

The service exports `authentikate:service/api@0.1.0` with `signup`, `login`,
and `validate`. Each accepts a JSON request body as bytes and returns a status
code and JSON body as bytes -- nothing else. The signing key, the issuer, the
token lifetime, the sender address and the dummy Argon2 cost parameters are
read by the service's own adapter from `authentikate:config/service@0.1.0` and
the crypto imports its world already has, so no caller can influence them.
See [api.wit](components/service/wit/api.wit).

The composed artifact exports `wasi:http/incoming-handler@0.2.4`, and the HTTP
gateway in [components/gateway](components/gateway) is what implements it:
it decides the request target's form, applies the Host/Origin policy, routes,
serves the three static assets, checks the method and media type, enforces the
16 KiB body limit and the 15-second read deadline, and sets the response
security headers. It has three imports -- `authentikate:service/api`,
`authentikate:config/policy` and `wasi:http` -- and that list is the security
claim: it parses no JSON, inspects no credential, and cannot reach a key,
because the signing seed is in `authentikate:config/service`, which only the
service's world imports. The part an attacker talks to has no import through
which a private key could arrive.

That leaves the host with the engine and its limits, admission control, the
storage directory preopen, and configuration, which it supplies through two interfaces
rather than one: `authentikate:config/service@0.1.0` carries the seed to the
service, `authentikate:config/policy@0.1.0` carries the origin rules to the
gateway, and the host is the only place the two meet. Neither is a grant of
`wasi:cli/environment`, which would be read access to every variable in the
process for a handful of named values. Only the storage component imports
filesystem access, restricted to `STORAGE_DIR` (default `accounts/`) mounted at
`/accounts`. No environment or network access is granted, and there is no outbound HTTP: `wasmtime-wasi-http` is built
without `default-send-request` and the host's `send_request` refuses.

The parser supports a restricted JSON subset: objects, printable ASCII strings
without escapes, non-negative integers, and booleans. String keys and values
accept only bytes `0x20` through `0x7E`, excluding double quote and backslash.
Emails and passwords therefore cannot contain Unicode or control characters.
JSON whitespace outside strings is unchanged. It rejects duplicate keys, arrays,
`null`, negative numbers, and floating-point numbers. The printer does not escape
strings, so hosts must also supply an issuer (`iss`) in the same printable ASCII
subset. See [Json.v](components/service/theories/Json.v).

Time comes from `wasi:clocks/wall-clock@0.2.0`. The component reads the clock
once per request and passes Unix seconds into the pure Rocq core, which retains
explicit time arguments for deterministic tests and expiration reasoning.

### Clock Trust Assumption

The host is trusted to supply an accurate current UTC-referenced POSIX timestamp.
WASI's "wall clock" is the appropriate interface for this: its
[`now` contract](components/service/wit/deps/clocks/wall-clock.wit) specifies seconds since
`1970-01-01T00:00:00Z`, not local civil time or elapsed time. This matches JWT's
[`NumericDate`](https://www.rfc-editor.org/rfc/rfc7519.html#section-2), which
ignores leap seconds. A monotonic clock cannot replace it for absolute expiry
because it has no UTC epoch.

JWT `exp` is an absolute timestamp, computed at login as `now + ttl`.
Validation requires `now < exp`, so the token expires at `exp` itself. The
freshness proof is relative to the supplied `now`; it does not prove that the
host clock reflects real-world time. WASI permits wall-clock adjustments, and
the service does not detect rollback or apply a clock-skew allowance. A slow or
rolled-back clock can accept a token past its real-world expiry; a fast clock
can reject one prematurely. Deployments must maintain a trustworthy,
synchronized host clock.

### Other Providers

Storage uses `authentikate:storage/accounts@0.1.0`, whose only operations are
`get` and atomic create-if-absent. Signup checks for an existing account,
enrolls the password, creates the record only if the key is still absent, then
sends a welcome email. Losing a create race answers `409` instead of overwriting
the winner; no overwrite operation or resource handles are exposed at all.
The stored record is printed by the Rocq core from the fields it read out of
the Argon2 component's JSON, not from that JSON itself: exactly eight fields,
no nested objects, no cost parameter wider than a `u32`, and a
provider-supplied email is refused. Success (`201`) requires both an
acknowledged create and email acceptance; known accounts return `409` without
sending email. The initial read only avoids paying for an Argon2 enrollment
that cannot be used; uniqueness rests on the create, and so on the provider
implementing create-if-absent atomically. Write durability depends on the
storage provider. The composed demo uses [components/storage](components/storage),
which writes complete temporary files, syncs them, and atomically hard-links
them to SHA-256-derived account paths before syncing the directory. Accounts
survive requests and host restarts; the signing key does not. See its README
for the disk envelope, filesystem assumptions, uncertain sync outcomes, and
orphan-temporary cleanup. The host creates new storage directories with mode
0700 on Unix; existing directories must already have appropriate permissions.

Cryptography uses custom component interfaces in `components/crypto/wit/`: Argon2 enrollment
and verification, and HMAC-SHA-256 generation and verification. Both HMAC operations
use the same opaque u32 handle; secret keys never enter the Rocq heap. Rust implementations can be
built separately in the Nix development shell, which includes the Rust
`wasm32-unknown-unknown` target:

```sh
nix develop --command make crypto-components
```

JWTs use only HS256 with the full 32-byte HMAC-SHA-256 tag. The component imports
exactly 32 random key bytes and compares tags with `subtle` constant-time equality.
There is no public key: anyone who can independently verify with this secret
can also mint tokens. EdDSA, `none`, and other algorithm headers are rejected,
not selected dynamically. Previously issued EdDSA tokens are not supported.

`libcrux-hmac` 0.0.9 contains safe Rust translated from HACL*-origin verified C;
the upstream proofs concern primitive memory safety, functional correctness and
source-level secret independence. They do not cover this wrapper, the tag
comparison, Wasm compilation or runtime timing. Imported and stored key buffers
are zeroized, but library temporaries and ABI/host copies are not guaranteed
wiped. See [the HMAC component](components/crypto/hmac).

The service component imports these crypto interfaces rather than bundling an
implementation. Argon2 enrollment uses `wasi:random/random@0.2.0` for fresh salts.
The standard WIT declarations used by the build are pinned in `components/service/wit/deps/` and
`components/crypto/wit/deps/`.

## CertiRocq

A custom [version](https://github.com/womeier/certirocq/tree/imports) of CertiRocq is used.
It has experimental support for foreign function calls resolved via Wasm module imports.


## Trusted Computing Base

What the proofs in [Proofs.v](components/service/theories/Proofs.v) establish is
deliberately narrow: structural properties of the Rocq functions, universally
quantified over records of crypto, storage and email operations, with every
`Print Assumptions` closed under the global context. Everything listed below is
outside that — trusted, tested, or assumed — and is collected here so the
boundary can be read rather than inferred. [PLAN.md](PLAN.md) argues the
individual cases; this is the inventory.

### General

- **The proofs are about the Rocq core, not about the module that runs.** The
  pinned CertiRocq's correctness does not extend across foreign calls: a
  registered `Axiom` has no evaluation rule in the source language, so no
  theorem relates `Api.handle` to the emitted Wasm. The seven registrations in
  [extraction.v](components/service/theories/extraction.v) are where the chain
  is cut, and it is cut deliberately.
- **Post-compilation rewriting.** `components/service/build.mjs` merges the
  extracted core with hand-written adapters, removes link-only exports, prunes
  with `wasm-opt`, embeds WIT and runs `wasm-tools component new`. Every one of
  those steps transforms the module after the compiler is done with it.
- **The engine.** wasmtime's optimising JIT and its implementation of the
  component model's canonical ABI, plus jco and Node in the JavaScript test
  suites. None of these is verified against a mechanised Wasm semantics.
- **HTTP parsing and the request/response mapping.** Moving to
  `wasi:http/incoming-handler` added hyper's HTTP/1.1 parser and
  `wasmtime-wasi-http`'s mapping from wire bytes onto `incoming-request`,
  `fields` and the body streams, in exchange for deleting the host's own
  request handling. The gateway therefore never sees a request line: it is
  handed a method, a `path-with-query` and an authority that something else
  decided. One consequence is visible in the tests -- `wasmtime-wasi-http`
  takes the authority from the URI in preference to the `Host` header, so an
  absolute-form target is refused by the Host/Origin policy (403) rather than
  by the origin-form check (400). [coq-http](https://github.com/liyishuai/coq-http)
  is the natural yardstick for exactly this layer, being an HTTP/1.1
  specification in Coq built for model-based testing of servers; it is not
  used here, and its HTTP/1.1 parser is the part `wasi:http` makes redundant.
- **The service's adapter assembles its own configuration.** The 500 for a
  seed HMAC-SHA-256 refuses, the constant dummy salt, and the zero-filled dummy tag
  whose length tracks `recommended-params` are all hand-written WebAssembly in
  `components/service/adapters/service.wat`, unproved like the rest of that
  glue. The differential tests in `tests/component.mjs` pin the assembled
  record field by field, including that the dummy cost parameters equal the
  enrolled ones -- which is what keeps the absent-account login path
  indistinguishable by duration.
- **Routing and the origin policy are not proved.** They moved from the host
  into a component, which makes the artifact self-contained and the checks
  unit-testable without an engine, but `components/gateway` is ordinary Rust.
  Nothing in Rocq says that `/api/login` reaches `login`, that a foreign
  `Origin` is refused, or that the security headers are set. A separate proved
  HTTP-policy component could bring these under proof without widening the
  authentication service; see [TODO.md](TODO.md).
- **Cryptographic hardness.** The security direction,
  `accepted_implies_authenticated`, is conditional on a signing-oracle
  hypothesis: that verification accepts only messages this service signed. That
  is an idealized security assumption, not a theorem about HMAC. Every holder
  of the shared secret can mint tokens, so the hypothesis also requires that
  no other issuer is provisioned with it. Implementation verification alone
  does not discharge that deployment assumption. The other two crypto
  hypotheses assume only *correctness* — that sign-then-verify and
  enroll-then-verify agree — and say nothing about unforgeability.
- **Timing.** No constant-time property is established anywhere. The `Secret`
  seal is a source-level discipline; the JSON parser runs over the password
  before it can be sealed; Argon2id's addressing is data-dependent by design;
  and the engine may add behaviour no property of the module predicts.
  `login_hides_existence` is a statement about response *values*, not
  durations, and no `dudect`-style measurement exists yet.
- **Time and entropy.** The clock, as described above. Salt freshness depends on
  `wasi:random/random@0.2.0` and the demo's signing seed on the host's
  `getrandom`; neither is proved to be unpredictable.
- **Host-supplied configuration.** The shared-key handle, the
  issuer, the TTL and the dummy salt, tag and cost parameters all arrive from
  outside. A signing key shared across deployments or
  dummy parameters that do not match what stored records carry are all outside
  what the proofs can see.
- **Rate limiting, replay and revocation.** No throttling is implemented, so
  online password guessing is limited only by Argon2's cost. Tokens are bearer
  tokens with an `exp` and nothing else, and `validate_ignores_the_store` proves
  that no state a deployment can reach will stop a fresh, well-signed token from
  validating.
- **Transport and operations.** There is no TLS; the demo listens on loopback,
  with `LISTEN`/`PUBLIC_ORIGIN` for a trusted proxy. Key custody, rotation,
  recovery tooling, backup and audit logging are not implemented. Account
  durability relies on the storage filesystem's sync guarantees.
- **Supply chain.** The Nix pins (the CertiRocq fork, `rocq-base64`), the Cargo
  lockfile, and the `womeier.cachix.org` binary cache — which the macOS demo
  path fetches prebuilt components from rather than building them.

### Per component

- **Rocq service core** (`components/service/theories/`) — the verified part,
  with three things still trusted inside it. The seven FFI axioms are the
  first. The second is the `Secret` seal: it survives erasure only because
  `Secret.of_bytes` is registered as a foreign *identity*, so the guarantee
  rests on that adapter actually being the identity. The third is that no
  strength floor is enforced on stored Argon2 cost parameters —
  `Store.public_of_json` checks only that each fits a `u32`, so a record naming
  a trivial cost would be verified at that cost. Separately, the JSON parser's
  fuel is fixed at 16, which makes a sufficiently nested body a rejection
  rather than a parse.
- **Wasm FFI adapters** (`components/service/adapters/*.wat`) — hand-written,
  unproved, and exercised only by `tests/ffi-adapters.mjs`. They encode the
  backend's value representation, which was probed from its output rather than
  derived from a theorem; they restore four-byte heap alignment after
  byte-oriented foreign allocations; they grow memory themselves rather than
  trusting the headroom the backend leaves; and they call curried closures by
  hand. `store.wat` additionally carries the RFC 3629 validator that stands
  between an attacker-controlled email and the canonical ABI's trap on
  ill-formed UTF-8, which makes it the most security-relevant unproved code
  here.
- **Rust host** (`host/`) — roughly a thousand lines of unverified Rust outside
  the component: route dispatch from `/api/*`, the 16 KiB streaming body limit
  and read deadline, the JSON content-type check and the Host/Origin policy,
  bounded admission, fuel and a 128 MiB memory ceiling, a fresh composition per
  request, ephemeral seed generation with per-instance key import, startup
  derivation of the dummy salt, password and parameters, and the static demo
  assets. Storage is a separate component; the host grants only its dedicated
  directory preopen rather than implementing keyvalue operations.
- **Argon2 component** (`components/crypto/argon2/`) — RustCrypto's `argon2`,
  trusted for verification correctness, for the quality of the salt it draws
  from `wasi:random`, for `recommended-params`, and for returning the tag
  already base64url-encoded, which is what keeps encoded secret bytes out of
  Rocq. Enrollment selects Argon2id; verification hashes under the parameters
  read back from the stored record.
- **HMAC-SHA-256 component** (`components/crypto/hmac/`) -- libcrux's HACL*-origin
  implementation, the unproved wrapper and constant-time comparison, and the
  key table keeping shared secrets out of the Rocq heap behind opaque `u32`
  handles. Key wiping is partial, as noted above; the provisioning host retains
  the secret, and the demo still generates a new key on restart.
- **Email component** (`components/email/`) — writes the message to stdout.
  Acceptance is not delivery, and the welcome message carries the fact that an
  account exists onto whatever path the mail takes.
- **Storage component** (`components/storage/`) -- unproved Rust, SHA-256 key
  hashing, and WASI/filesystem hard-link and sync semantics form the concrete
  basis for the storage hypotheses. The interface exposes only get/create;
  publication must be atomic or signup's uniqueness is lost. Durability and
  lookup timing remain provider/filesystem behaviour, and local modification
  of account files is outside the threat model.
