# authentikate

An authentication backend written in Rocq, compiled to WebAssembly by CertiRocq.

## Building

Prebuilt artifacts are available via womeier's cachix.
```
cachix use womeier  # optional
nix build
```

The flake includes [rocq-base64](https://github.com/womeier/rocq-base64), built
with the same Rocq and MetaRocq toolchain as CertiRocq. The service uses its
MetaRocq bytestring instance with strict, unpadded base64url encoding.
The default build checks the Rocq proofs and extracts the real signup, login,
and validation service. It produces `authentikate.component.wasm` and
`authentikate.core.wasm` in the Nix output, or under `build/` with:

```sh
nix develop --command make
nix develop --command make test
```

`theories/extraction.v` remains a separate echo smoke test; the service is
extracted from `theories/extractions.v`.

## Component Interfaces

The service exports `authentikate:service/api@0.1.0` with `signup`, `login`,
and `validate`. Each accepts configuration, the current Unix time, and a JSON
request body, and returns an HTTP status and JSON body. See `wit/service.wit`.

Storage uses the standard `wasi:keyvalue/store@0.2.0-draft` interface. Signup
checks for an existing account, enrolls the password, and persists the record
through `bucket.set`. Success requires an acknowledged write (`201`); known
accounts return `409`. Get-then-set is not atomic: production account uniqueness
requires a transactional store or external serialization.

Cryptography uses custom component interfaces in `crypto/wit/`: Argon2 enrollment
and verification, and Ed25519 signing and verification. Signing uses opaque u32
handles; private keys never enter the Rocq heap. Rust implementations can be
built separately, with the Rust `wasm32-unknown-unknown` target installed:

```sh
nix develop --command make crypto-components
```

The service component imports these crypto interfaces rather than bundling an
implementation. Argon2 enrollment uses `wasi:random/random@0.2.0` for fresh salts.
The standard WIT declarations used by the build are pinned in `wit/deps/` and
`crypto/wit/deps/`.

## Web Demo

Build the component first, then run the local test frontend:

```sh
npm ci
npm run dev
```

Open http://127.0.0.1:3000 to sign up, log in, and validate a token.
`npm run test:web` exercises the actual component over HTTP with native Argon2
and Ed25519 providers. The demo implements WASI keyvalue with an in-memory map;
accounts and signing keys disappear on restart. It is loopback-only by default
and is not a production server. See `web/README.md` for details.

## CertiRocq

A custom [version](https://github.com/womeier/certirocq/tree/imports) of CertiRocq is used.
It has experimental support for foreign function calls resolved via Wasm module imports.
The pinned compiler adds a force argument to registered constants; explicit
registration arities and adapters account for it. The component boundary also
restores heap alignment after foreign calls. Runtime tests cover both requirements.
The existing end-to-end `login_then_validate` theorem remains admitted; a passing
build does not establish the whole service's security or timing behavior.
