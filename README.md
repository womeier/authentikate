# authentikate

An experimental authentication backend with signup, login and JWT validation.
The main logic is written in Rocq, compiled to WebAssembly with CertiRocq
and composed with Rust providers into a single Wasm component.


## Run The Demo

```sh
cachix use womeier
nix run .#authentikate-local
# open http://localhost:3000
```

Tested on Linux. Apple Silicon macOS support is experimental and untested:
it should fetch the prebuilt Wasm components from `womeier.cachix.org` and compile only the Rust host locally.

See [host/README.md](host/README.md) for development builds, tests, configuration.

## Request Behavior

Request and response bodies are JSON. The table uses shorthand field notation.

| Method | Path | Request | Successful Response |
| --- | --- | --- | --- |
| POST | `/api/signup` | `{email, password}` | `201 {}` |
| POST | `/api/login` | `{email, password}` | `200 {token}` |
| POST | `/api/validate` | `{token}` | `200 {valid, claims?}` |

- Signup atomically creates an account, then sends a welcome email. Existing
  accounts and lost create races return `409`. Storage, enrollment or email
  failures return `500`. Email failure does not roll back the account, so a
  retry can return `409`.
- Login returns the same `401` response for wrong credentials and missing
  accounts. For missing accounts, a dummy Argon2 computation helps reduce
  timing differences that could reveal whether an account exists.
  Storage refusal or signing failure can return `500`.
- Validation checks the MAC, issuer and expiry. Invalid tokens return
  `200 {valid:false}`. Validation never reads account storage, so account
  changes cannot revoke tokens.


## Architecture

- **Rocq service:** parses requests, implements authentication and constructs
  account records and JWT claims. Its [API](components/service/wit/api.wit)
  accepts request bytes and returns a status code and response bytes.
- **Rust gateway:** routes HTTP requests, enforces Host/Origin policy, media
  types, a 16 KiB body limit and a 15-second body-read deadline, serves demo
  assets and sets security headers. It has no access to the signing key.
- **Providers:** [Argon2](components/crypto/argon2) for passwords,
  [HMAC-SHA-256](components/crypto/hmac) for HS256 tokens,
  [file-backed storage](components/storage) with atomic create-if-absent, and
  [email](components/email) that currently writes to stdout. Secret keys stay
  outside the Rocq heap behind opaque handles.
- **Rust host:** runs Wasmtime, supplies configuration and capabilities, and
  enforces admission and execution limits. Each request gets a fresh component
  instance. Only storage receives filesystem access, restricted to
  `STORAGE_DIR` (default `run/`); no environment or outbound network access
  is granted to the components.

The composed artifact exports `wasi:http/incoming-handler@0.2.4`. See
[host/README.md](host/README.md) for composition and runtime details.

## Security And Limits

This is a demo, not an end-to-end verified authentication system.

- [Rocq proofs](components/service/theories/Proofs.v) establish properties of
  the pure core under explicit provider assumptions. They do not verify the
  foreign-call boundary, adapters, compilation pipeline, Rust components,
  runtime or deployment, and do not establish whole-service constant-time
  behavior. See [PLAN.md](PLAN.md) for the verification boundary.
- JWTs use only HS256 with a 32-byte secret key and full HMAC-SHA-256 tags.
  Signing and verification use the same key; this deployment does not distribute
  it to independent verifiers.
- Accounts persist across host restarts; the demo's signing key does not, so
  previously issued tokens stop validating after restart. Storage durability
  depends on filesystem hard-link and sync guarantees; protect account files.
- Expiry requires `now < exp` and trusts the host's UTC-referenced POSIX clock.
  Clock rollback is not detected, and no clock-skew allowance is applied.
- There is no rate limiting, token revocation, built-in TLS, key rotation or
  account recovery tooling. Welcome emails expose recipient addresses on
  stdout. Keep the demo on loopback unless testing a controlled proxy.

## Further Reading

- [Host guide](host/README.md): builds, configuration and tests.
- [Design and verification boundary](PLAN.md).
- [Pending work](TODO.md).
- [Storage guarantees and filesystem assumptions](components/storage/README.md).
- [HMAC implementation and proof limitations](components/crypto/hmac/README.md).
