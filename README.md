# authentikate

An authentication backend written in Rocq, compiled to WebAssembly by CertiRocq.

Deferred work is tracked in [TODO.md](TODO.md).

## Architecture Figures

[`report/architecture.tex`](report/architecture.tex) shows only the backend components,
languages, types, verification status, and clickable implementation, theorem,
and adapter links. [`report/login-flow.tex`](report/login-flow.tex) is a separate TikZ
sequence diagram of frontend/backend login communication, including successful
token issuance and failure responses. Build the report with its dedicated
development shell, which provides Tectonic without the Rocq/Rust dependencies:

```sh
mkdir -p build
nix develop .#report --command tectonic --outdir build report/main.tex
```

The PDF is `build/main.pdf`. For an interactive report shell, use
`nix develop .#report`. The backend
figure distinguishes active Rust providers, alternative deployments, proved
source properties, tested boundaries, and external assumptions; it contains no
browser UI or frontend host diagram.

For a sandboxed build, run `nix build .#report`; the PDF is `result/main.pdf`.
Nix fetches a hash-pinned cache of the required TeX resources and compiles offline.

## Building

Prebuilt artifacts are available via womeier's cachix.
```
cachix use womeier  # optional
nix build
```

The flake includes [rocq-base64](https://github.com/womeier/rocq-base64), built
with the same Rocq toolchain as CertiRocq, without a MetaRocq dependency.
The service defines its MetaRocq bytestring instance, strict unpadded base64url
wrappers, and correctness proofs in `components/service/theories/Base64.v`.
The default build checks the Rocq proofs and extracts the real signup, login,
and validation service. It produces `authentikate.component.wasm` and
`authentikate.core.wasm` in the Nix output, or under `build/` with:

```sh
nix develop --command make -C components/service
nix develop --command make -C components/service test
```

The service is extracted from `components/service/theories/extraction.v`. Its intermediate Wasm is
written to `build/Authentikate.extraction.authentikate_api.wasm`, not the project root.

Sources are grouped under `components/service/` (Rocq sources, WAT adapters,
service WIT and assembly), `components/crypto/` and `components/email/`
(Rust provider crates), `host/` (Rust host and embedded assets),
`tests/` (test suites), and `report/` (report sources and figures). Generated
service artifacts live in `build/`; all Rust crates share the root `Cargo.lock`
and `target/` directory.

The root Cargo workspace selects `host/` by default, so `cargo run --locked`
and `cargo test --locked` work from the repository root. The provider crates are
workspace members, built and tested explicitly with `-p authentikate-argon2`,
`-p authentikate-ed25519`, or `-p authentikate-email`. Rocq compilation and service
assembly live in `components/service/Makefile`, with their own `_RocqProject`.
Run `make -C components/service` to build the service or add `test` to test it.
The root Makefile forwards `rocq`, `component`, `test`, and `clean` to this
standalone build; provider and host commands run from the repository root.

## Component Interfaces

The service exports `authentikate:service/api@0.1.0` with `signup`, `login`,
and `validate`. Each accepts configuration and a JSON
request body, and returns an HTTP status and JSON body. See `components/service/wit/service.wit`.

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

A verified calendar library such as
[FV Time (CPP 2024)](https://doi.org/10.1145/3636501.3636958) could verify future
calendar-to-timestamp conversions using POSIX semantics. It would not establish
the accuracy of the live clock or remove this host trust assumption.

### Other Providers

Storage uses the standard `wasi:keyvalue/store@0.2.0-draft` interface. Signup
checks for an existing account, enrolls the password, and persists the record
through `bucket.set`, then sends a welcome email. Success (`201`) requires both
an acknowledged write and email acceptance; known accounts return `409` without
sending email. Get-then-set is not atomic: production account uniqueness
requires a transactional store or external serialization.

Cryptography uses custom component interfaces in `components/crypto/wit/`: Argon2 enrollment
and verification, and Ed25519 signing and verification. Signing uses opaque u32
handles; private keys never enter the Rocq heap. Rust implementations can be
built separately, with the Rust `wasm32-unknown-unknown` target installed:

```sh
nix develop --command make crypto-components
```

The service component imports these crypto interfaces rather than bundling an
implementation. Argon2 enrollment uses `wasi:random/random@0.2.0` for fresh salts.
The standard WIT declarations used by the build are pinned in `components/service/wit/deps/` and
`components/crypto/wit/deps/`.

## Email Components

Two interchangeable providers export `authentikate:email/sender@0.1.0` from
`components/email/wit/email.wit`: a stdout backend for tests and a Lettermint backend for
production. Build them with the same Rust target as the crypto providers:

```sh
nix develop --command make email-components
nix develop --command make test-email
```

See `components/email/README.md` for configuration, host capabilities, and delivery semantics.
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
Rocq or Wasm build tools. Rust 1.97 or newer is required.

`cargo test --locked` exercises the composed service over HTTP, including actual
Wasm Argon2/Ed25519 and stdout email, signature rejection, concurrency, request
limits and Host/Origin policy. The host never implements or forwards the service's
crypto imports: WAC connects the existing Rust Wasm components directly.
The demo supplies in-memory WASI keyvalue, clock, random and stdout capabilities.
Accounts and signing keys disappear on restart. It binds loopback by default;
`LISTEN` and `PUBLIC_ORIGIN` configure an explicit alternative. This is not a
production server. See `host/README.md` for details.

## CertiRocq

A custom [version](https://github.com/womeier/certirocq/tree/imports) of CertiRocq is used.
It has experimental support for foreign function calls resolved via Wasm module imports.
The pinned compiler adds a force argument to registered constants; explicit
registration arities and adapters account for it. The component boundary also
restores heap alignment after foreign calls. Runtime tests cover both requirements.
The existing end-to-end `login_then_validate` theorem remains admitted; a passing
build does not establish the whole service's security or timing behavior.
