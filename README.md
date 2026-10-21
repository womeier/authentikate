# authentikate

An authentication backend written in Rocq, compiled to WebAssembly by CertiRocq.

Deferred work is tracked in [TODO.md](TODO.md).

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

The service is extracted from `theories/extraction.v`.

## Component Interfaces

The service exports `authentikate:service/api@0.1.0` with `signup`, `login`,
and `validate`. Each accepts configuration and a JSON
request body, and returns an HTTP status and JSON body. See `wit/service.wit`.

Time comes from `wasi:clocks/wall-clock@0.2.0`. The component reads the clock
once per request and passes Unix seconds into the pure Rocq core, which retains
explicit time arguments for deterministic tests and expiration reasoning.

Storage uses the standard `wasi:keyvalue/store@0.2.0-draft` interface. Signup
checks for an existing account, enrolls the password, and persists the record
through `bucket.set`, then sends a welcome email. Success (`201`) requires both
an acknowledged write and email acceptance; known accounts return `409` without
sending email. Get-then-set is not atomic: production account uniqueness
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

## Email Components

Two interchangeable providers export `authentikate:email/sender@0.1.0` from
`email/wit/email.wit`: a stdout backend for tests and a Lettermint backend for
production. Build them with the same Rust target as the crypto providers:

```sh
nix develop --command make email-components
nix develop --command make test-email
```

See `email/README.md` for configuration, host capabilities, and delivery semantics.
Signup imports this interface and sends a plain-text welcome message after the
account write succeeds. Configure its sender with the API's `email-from` field.
Email failure returns `500` but leaves the account stored; retrying signup returns
`409`, without resending. There is no email verification or durable retry queue.

## Web Demo

Build the service, Rust crypto providers and stdout email provider, compose them
at the component level with WAC, then start the Rust web host from the root:

```sh
nix develop
make host-component
cargo run --locked
```

Open http://127.0.0.1:3000 to sign up, log in, and validate a token.
The Nix development shell includes WAC 0.12.0, the Rocq/Node/Binaryen/wasm-tools
toolchain, and a locked Fenix Rust toolchain with the `wasm32-unknown-unknown`
standard library, plus JCO, Python and curl. No rustup or npm setup is needed. If all four
`build/*.component.wasm` inputs already exist, use
`make compose-host` instead. After composition, `cargo run` needs no Node, WAC,
Rocq or Wasm build tools. Rust 1.88 or newer is required.

`cargo test --locked` exercises the composed service over HTTP, including actual
Wasm Argon2/Ed25519 and stdout email, signature rejection, concurrency, request
limits and Host/Origin policy. The host never implements or forwards the service's
crypto imports: WAC connects the existing Rust Wasm components directly.
The demo supplies in-memory WASI keyvalue, clock, random and stdout capabilities.
Accounts and signing keys disappear on restart. It binds loopback by default;
`LISTEN` and `PUBLIC_ORIGIN` configure an explicit alternative. This is not a
production server. See `web/README.md` for details.

## CertiRocq

A custom [version](https://github.com/womeier/certirocq/tree/imports) of CertiRocq is used.
It has experimental support for foreign function calls resolved via Wasm module imports.
The pinned compiler adds a force argument to registered constants; explicit
registration arities and adapters account for it. The component boundary also
restores heap alignment after foreign calls. Runtime tests cover both requirements.
The existing end-to-end `login_then_validate` theorem remains admitted; a passing
build does not establish the whole service's security or timing behavior.
