# authentikate

An experimental authentication backend with signup, login and JWT validation.
The main logic is written in Rocq, compiled to WebAssembly with CertiRocq
and composed with Rust providers into a single Wasm component.


## Run The Demo

Run from the repository root:

```sh
cachix use womeier
nix run .#authentikate-local
# open http://localhost:3000
```

## Live Email

`nix run .#authentikate-live` runs the same loopback demo with direct SMTP
instead of stdout. 
Requires local SMTP MTA listening on `127.0.0.1:25`.
```sh
nix run .#authentikate-live
```

Open `http://localhost:3000` and sign up with an address you control. Signup sends
a real welcome email through your configured mail system. Existing accounts return
`409` without sending another email. A successful send means the SMTP server's
final `250` acceptance after `DATA`, not confirmed delivery. An email failure
returns `500` after account creation;
the account remains stored and retrying signup does not resend.

## Build And Test

```sh
nix develop --command make app-component
nix develop --command make test-app
nix develop --command make test
nix develop --command cargo test --locked --workspace
nix build .#authentikate-app-component
nix develop --command make test-email-stdout test-email-smtp
nix build .#authentikate-live-component
```

## Configuration

[config.example.json](config.example.json) supplies a safe printable, escape-free
issuer, token TTL, sender and loopback port-3000 authority policy. Configure
`service.issuer`, `service.token_ttl_seconds` and `service.email_from` in
`/config/config.json`; these are not environment-variable settings. Issuers must
be nonblank printable ASCII without quotes or backslashes, because the Rocq JSON
printer does not escape them. See the [config provider](components/config/README.md)
for validation rules.


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
  assets and sets security headers. It imports neither filesystem interfaces nor
  the signing-key configuration interface.
- **Providers:** [Argon2](components/crypto/argon2) for passwords,
  [HMAC-SHA-256](components/crypto/hmac) for HS256 tokens,
  [file-backed storage](components/storage) with atomic create-if-absent, and
  [email](components/email) that writes to stdout by default or sends through
  direct SMTP to the local MTA in the live composition. Secret keys stay
  outside the Rocq heap behind opaque handles.
- **Config provider:** reads provisioned JSON and the persistent signing key,
  exporting service settings to the service and origin policy to the gateway.
- **Wasmtime CLI:** serves the final component with WASI capabilities and
  resource limits. Instance reuse is disabled so each request has fresh component
  state. The custom Rust host is no longer part of the production path.

The composed artifact exports `wasi:http/incoming-handler@0.2.4`. See
[composition.wac](composition.wac) for the provider wiring.

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
- Accounts and the provisioned signing key persist across process restarts.
  Storage durability depends on filesystem hard-link and sync guarantees;
  protect account files and the key.
- Expiry requires `now < exp` and trusts the host's UTC-referenced POSIX clock.
  Clock rollback is not detected, and no clock-skew allowance is applied.
- There is no rate limiting, token revocation, built-in TLS, key rotation or
  account recovery tooling. Welcome emails expose recipient addresses on
  stdout. Keep the demo on loopback unless testing a controlled proxy.
- The CLI limits above are conservative bounds, not equivalence to the removed
  host's admission controls. In particular, its exact overload-`503` response
  contract no longer applies. Wasmtime handles component traps itself; those
  responses need not have the gateway's JSON format or security headers.
  Fuel and memory limits are not a wall-clock deadline
  for crypto or a complete production resource policy.

## Further Reading

- [Configuration provider](components/config/README.md): provisioning and validation.
- [Design and verification boundary](PLAN.md).
- [Pending work](TODO.md).
- [Storage guarantees and filesystem assumptions](components/storage/README.md).
- [HMAC implementation and proof limitations](components/crypto/hmac/README.md).
