# authentikate

An experimental authentication backend with signup, login and JWT validation.
The main logic is written in Rocq, compiled to WebAssembly with CertiRocq
and composed with Rust providers into a single Wasm component.

## Demo

Run from the repository root:

```sh
cachix use womeier
nix run .#authentikate-local
```

Open <http://localhost:3000>. The local demo writes welcome emails to stdout.

To send emails through a local SMTP server on `127.0.0.1:25` instead:

```sh
nix run .#authentikate-live
```

## Behavior

Request and response bodies are JSON.

| Method | Path | Request | Successful Response |
| --- | --- | --- | --- |
| POST | `/api/signup` | `{email, password}` | `201 {}` |
| POST | `/api/login` | `{email, password}` | `200 {token}` |
| POST | `/api/validate` | `{token}` | `200 {valid, claims?}` |

- Signup atomically creates an account, then sends a welcome email.
- Login returns the same `401` response for wrong credentials and missing
  accounts. For missing accounts, a dummy Argon2 computation helps reduce
  timing differences that could reveal whether an account exists.
  Storage refusal or signing failure can return `500`.
- Validation checks the MAC, issuer and expiry. Invalid tokens return
  `200 {valid:false}`. Validation never reads account storage, so account
  changes cannot revoke tokens.

## Build and test

Build the composed HTTP component and run the flake checks, including service
proofs, adapter tests and HTTP integration tests with real providers:

```sh
nix build .#authentikate-app-component
nix flake check
```

Build the SMTP composition:

```sh
nix build .#authentikate-live-component
```

For incremental development and additional provider tests:

```sh
nix develop
make app-component
make test
make test-app
cargo test --locked --workspace
make test-email-stdout test-email-smtp
```

## Configuration

See [config.example.json](config.example.json) for the sender address, issuer,
token lifetime and HTTP security policies. The
[configuration provider documentation](components/config/README.md) describes
provisioning and signing-key management.

## Architecture

Components live under `components/`, with WIT interfaces alongside them and
shared definitions in `wit/`.

- **Rocq service:** parses requests, implements authentication and constructs
  account records and JWT claims. Its [API](components/service/wit/api.wit)
  accepts request bytes and returns a status code and response bytes.
- **Rust gateway:** routes HTTP requests, enforces Host/Origin policy, media
  types, a 16 KiB body limit and a 15-second body-read deadline, serves demo
  assets and sets security headers.
- **Providers:** [Argon2](components/crypto/argon2) for passwords,
  [HMAC-SHA-256](components/crypto/hmac) for HS256 tokens,
  [file-backed storage](components/storage) with atomic create-if-absent, and
  [email](components/email) that writes to stdout by default or sends through
  direct SMTP to the local MTA in the live composition. Secret keys stay
  outside the Rocq heap behind opaque handles.
- **Config provider:** reads provisioned JSON and the persistent signing key,
  exporting service settings to the service and origin policy to the gateway.

Wasmtime serves the final component with WASI capabilities and resource limits.
Instance reuse is disabled so each request has fresh component state.

The composed artifact exports `wasi:http/incoming-handler@0.2.4`.
See [composition.wac](composition.wac) for the provider wiring.

## Security and limits

This is a demo, not an end-to-end verified authentication system.

- [Rocq proofs](components/service/theories/Proofs.v) establish properties of
  the pure core under explicit assumptions. They do not verify the
  foreign-call boundary, adapters, compilation pipeline, Rust components,
  runtime or deployment, and do not establish whole-service constant-time
  behavior. See [PLAN.md](PLAN.md) for the verification boundary.
- JWTs use only HS256 with a 32-byte secret key and full HMAC-SHA-256 tags.
  Signing and verification use the same key; this deployment does not distribute
  it to independent verifiers.
- Accounts and the provisioned signing key persist across process restarts.
  Storage durability depends on filesystem hard-link and sync guarantees;
  protect account files and the key.
- Expiry requires `now < exp` and trusts the host's UTC-referenced POSIX clock.
  Clock rollback is not detected, and no clock-skew allowance is applied.
- There is no rate limiting, token revocation, built-in TLS, key rotation or
  account recovery tooling. Keep the demo on loopback unless testing a
  controlled proxy.

## Further reading

- [Design and verification boundary](PLAN.md).
- [Pending work](TODO.md).
- [Storage guarantees and filesystem assumptions](components/storage/README.md).
- [HMAC implementation and proof limitations](components/crypto/hmac/README.md).
