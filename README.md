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
