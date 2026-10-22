# authentikate

An experimental authentication backend service providing the following endpoints:
- `signup`: takes an email address and password and creates an account
- `login`: takes an email address and password and returns a JWT
- `validate`: takes and validates a JWT

The backend is a single Wasm component composed of the following individual components:
- main logic: written in Rocq, compiled to a Wasm module by CertiRocq, and wrapped inside a Wasm component.
- two crypto components: password hashing with RustCrypto's `argon2` crate, Ed25519 signatures from the `libcrux-ed25519` crate
- email sending component: writes the email to stdout (could be swapped with an actual implementation)


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
and `validate`. Each accepts a typed configuration record and a JSON request
body as bytes, and returns a status code and JSON body as bytes. Clients send
only the request body. See
[service.wit](components/service/wit/service.wit).

The composed artifact exports `wasi:http/incoming-handler@0.2.4`, and the HTTP
front-end in [components/frontend](components/frontend) is what implements it:
it decides the request target's form, applies the Host/Origin policy, routes,
serves the three static assets, checks the method and media type, enforces the
16 KiB body limit and the 15-second read deadline, sets the response security
headers, and assembles the `config` record the service needs. It parses no
JSON, inspects no credential and holds no key -- `config` carries an opaque
Ed25519 handle, and signing happens in the crypto component. WAC wires the
front-end to the *same* Argon2 and Ed25519 instances as the service, which is
what makes that handle valid in the service's view and the dummy cost
parameters the ones real records are enrolled under.

That leaves the host with the engine and its limits, admission control, the
account map, and configuration, which it supplies through
`authentikate:frontend/settings@0.1.0` -- a typed six-field record rather than a
grant of `wasi:cli/environment`. No guest filesystem, environment or network
access is granted, and there is no outbound HTTP: `wasmtime-wasi-http` is built
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

Storage uses the draft `wasi:keyvalue/store@0.2.0-draft2` interface together
with its `atomics` compare-and-swap. Signup checks for an existing account,
enrolls the password, creates the record only if the key is still absent, then
sends a welcome email. The create is a `cas.new`/`swap` pair, so losing a race
answers `409` instead of overwriting the winner; `bucket.set` is not imported
at all, which is why a host implementing only `store` cannot run the service.
The stored record is printed by the Rocq core from the fields it read out of
the Argon2 component's JSON, not from that JSON itself: exactly eight fields,
no nested objects, no cost parameter wider than a `u32`, and a
provider-supplied email is refused. Success (`201`) requires both an
acknowledged create and email acceptance; known accounts return `409` without
sending email. The initial read only avoids paying for an Argon2 enrollment
that cannot be used; uniqueness rests on the swap, and so on the provider
implementing compare-and-swap atomically. Write durability depends on the
storage provider; the demo's in-memory store is not durable.

Cryptography uses custom component interfaces in `components/crypto/wit/`: Argon2 enrollment
and verification, and Ed25519 signing and verification. Signing uses opaque u32
handles; private keys never enter the Rocq heap. Rust implementations can be
built separately in the Nix development shell, which includes the Rust
`wasm32-unknown-unknown` target:

```sh
nix develop --command make crypto-components
```

The Ed25519 wrapper wipes imported and stored seeds, but libcrux 0.0.10 does not
explicitly wipe its internal expanded-key temporaries. This is not a guarantee
of full secret erasure.

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
  request handling. The front-end therefore never sees a request line: it is
  handed a method, a `path-with-query` and an authority that something else
  decided. One consequence is visible in the tests -- `wasmtime-wasi-http`
  takes the authority from the URI in preference to the `Host` header, so an
  absolute-form target is refused by the Host/Origin policy (403) rather than
  by the origin-form check (400). [coq-http](https://github.com/liyishuai/coq-http)
  is the natural yardstick for exactly this layer, being an HTTP/1.1
  specification in Coq built for model-based testing of servers; it is not
  used here, and its HTTP/1.1 parser is the part `wasi:http` makes redundant.
- **Routing and the origin policy are not proved.** They moved from the host
  into a component, which makes the artifact self-contained and the checks
  unit-testable without an engine, but `components/frontend` is ordinary Rust.
  Nothing in Rocq says that `/api/login` reaches `login`, that a foreign
  `Origin` is refused, or that the security headers are set. Widening the Rocq
  `handle` to take a method, a path and the headers it cares about, and to
  return headers alongside the status and body, is what would bring these
  under proof; see [TODO.md](TODO.md).
- **Cryptographic hardness.** The security direction,
  `accepted_implies_authenticated`, is conditional on a signing-oracle
  hypothesis: that verification accepts only messages this service signed. That
  is an assumption about Ed25519, not a theorem, and no amount of
  implementation verification would discharge it. The other two crypto
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
- **Host-supplied configuration.** The signing-key handle, its public half, the
  issuer, the TTL and the dummy salt, tag and cost parameters all arrive from
  outside. A mismatched public key, a signing key shared across deployments, or
  dummy parameters that do not match what stored records carry are all outside
  what the proofs can see.
- **Rate limiting, replay and revocation.** No throttling is connected:
  `Backoff.v` proves its bounds and is deliberately unwired, so online password
  guessing is limited only by Argon2's cost. Tokens are bearer tokens with an
  `exp` and nothing else, and `validate_ignores_the_store` proves that no state
  a deployment can reach will stop a fresh, well-signed token from validating.
- **Transport and operations.** There is no TLS; the demo listens on loopback,
  with `LISTEN`/`PUBLIC_ORIGIN` for a trusted proxy. Key custody, rotation,
  recovery, durable storage, backup and audit logging are not implemented.
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
  assets. It also implements `wasi:keyvalue`'s `store` and `atomics` over a
  single `BTreeMap`: that implementation, comparing and writing under one
  mutex, is what discharges the storage hypotheses for the demo, and it is not
  durable.
- **Argon2 component** (`components/crypto/argon2/`) — RustCrypto's `argon2`,
  trusted for verification correctness, for the quality of the salt it draws
  from `wasi:random`, for `recommended-params`, and for returning the tag
  already base64url-encoded, which is what keeps encoded secret bytes out of
  Rocq. Enrollment selects Argon2id; verification hashes under the parameters
  read back from the stored record.
- **Ed25519 component** (`components/crypto/ed25519/`) — libcrux, trusted for
  signature correctness and strict verification, and for the key table that
  keeps private keys out of the Rocq heap behind opaque `u32` handles. Seed
  wiping is partial, as noted above.
- **Email component** (`components/email/`) — writes the message to stdout.
  Acceptance is not delivery, and the welcome message carries the fact that an
  account exists onto whatever path the mail takes.
- **Storage provider** — any provider other than the demo host must implement
  `cas.new`, `cas.current` and `swap` atomically, or signup's uniqueness is
  lost. Durability, and whether a lookup's duration depends on whether the key
  is present, are both provider behaviour.
