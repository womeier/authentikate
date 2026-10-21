# authentikate

An experimental authentication backend service providing the following endpoints:
- `signup`: takes an email address and password and creates an account
- `login`: takes an email address and password and returns a JWT
- `validate`: takes and validates a JWT

The backend is a single Wasm component composed of the following individual components:
- main logic: written in Rocq, compiled to a Wasm module by CertiRocq, and wrapped inside a Wasm component.
- two crypto components: password hashing with RustCrypto's `argon2` crate, Ed25519 signatures from the `ed25519-dalek` crate
- email sending: two implementations for the same component interface (1: writing the email to stdout, 2: actually sending an email)


## Building
The Nix flake is tested on `x86_64-linux`. The optional Cachix cache can avoid rebuilding e.g. the CertiRocq-fork this project uses.
```sh
cachix use womeier  # optional
nix build
```

This builds and tests the service, producing `result/authentikate.component.wasm`
and `result/authentikate.core.wasm`. It does not build or bundle the Rust crypto
and email providers; use the Web Demo instructions for the composed backend.

## Web Demo
Build the service, Rust crypto providers and stdout email provider, compose them
at the component level with WAC, then start the Rust web host from the root:

```sh
nix develop
make host-component
cargo run --locked
```

Open http://127.0.0.1:3000 to sign up, log in, and validate a token. The HTTP
routes are `POST /api/signup`, `POST /api/login`, and `POST /api/validate`;
requests require `Content-Type: application/json`.

The Nix development shell supplies the Rust toolchain, Wasm target, WAC, and
component build tools. The demo logs welcome emails to stdout rather than
delivering them. Accounts and signing keys are held in memory: restarting loses
accounts and invalidates previously issued tokens. This is not a production
server. See [host/README.md](host/README.md) for configuration and tests.

## Component Interfaces

The service exports `authentikate:service/api@0.1.0` with `signup`, `login`,
and `validate`. Each accepts a typed configuration record and a JSON request
body as bytes, and returns a status code and JSON body as bytes. The HTTP host
supplies configuration; clients send only the request body. See
[service.wit](components/service/wit/service.wit).

The parser supports a restricted JSON subset: objects, strings without escapes,
non-negative integers, and booleans. It rejects duplicate keys, arrays, `null`,
negative numbers, and floating-point numbers. In particular, passwords cannot
contain a double quote or backslash. The printer does not escape strings, so
hosts must also supply a JSON-safe issuer (`iss`), without quotes, backslashes,
or control characters. See [Json.v](components/service/theories/Json.v).

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

Storage uses the draft `wasi:keyvalue/store@0.2.0-draft` interface. Signup
checks for an existing account, enrolls the password, and stores the record
through `bucket.set`, then sends a welcome email. Success (`201`) requires both
an acknowledged write and email acceptance; known accounts return `409` without
sending email. Get-then-set is not atomic: production account uniqueness
requires a transactional store or external serialization. Write durability
depends on the storage provider; the demo's in-memory store is not durable.

Cryptography uses custom component interfaces in `components/crypto/wit/`: Argon2 enrollment
and verification, and Ed25519 signing and verification. Signing uses opaque u32
handles; private keys never enter the Rocq heap. Rust implementations can be
built separately in the Nix development shell, which includes the Rust
`wasm32-unknown-unknown` target:

```sh
nix develop --command make crypto-components
```

The service component imports these crypto interfaces rather than bundling an
implementation. Argon2 enrollment uses `wasi:random/random@0.2.0` for fresh salts.
The standard WIT declarations used by the build are pinned in `components/service/wit/deps/` and
`components/crypto/wit/deps/`.

## Email Components

Two interchangeable providers export `authentikate:email/sender@0.1.0` from
`components/email/wit/email.wit`: a stdout backend for tests and demos, and a
Lettermint backend for delivery through Lettermint. Build them with the same Rust
target as the crypto providers:

```sh
nix develop --command make email-components
nix develop --command make test-email
```

See `components/email/README.md` for configuration, host capabilities, and delivery semantics.
Signup imports this interface and sends a plain-text welcome message after the
account write succeeds. Configure its sender with the API's `email-from` field
(or `SIGNUP_EMAIL_FROM` in the demo host).
Email failure returns `500` but leaves the account stored; retrying signup returns
`409`, without resending. There is no email verification or durable retry queue.

## CertiRocq

A custom [version](https://github.com/womeier/certirocq/tree/imports) of CertiRocq is used.
It has experimental support for foreign function calls resolved via Wasm module imports.
