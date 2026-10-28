Written by LLMs. TODO: check.

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

On first run, the launcher creates private `run/config` and `run/accounts`
directories, copies the bundled `config.example.json` to `run/config/config.json`,
and generates a persistent 32-byte random signing key. Existing configuration
directories are left untouched: the launcher never overwrites configuration or
regenerates a missing or malformed key inside them. The provider requires exactly
unpadded base64url (RFC 4648 Section 5) decoding to 32 key bytes, with an optional trailing LF or
CRLF. Back up and protect the key along with the accounts;
keeping it preserves token validity across restarts, subject to expiry.

Existing raw binary `signing.key` files must be converted before starting this
version. Stop the server, then encode the existing key rather than generating a
new one, preserving token validity:

```sh
(umask 077; set -C; set -o pipefail; openssl base64 -A -in run/config/signing.key | tr '+/' '-_' | tr -d '=' > run/config/signing.key.base64) &&
  mv run/config/signing.key.base64 run/config/signing.key
```

Adjust the paths when using a custom configuration directory. Only run this
conversion on an old raw 32-byte key, not an already base64-encoded key.

The launcher uses Wasmtime from the pinned flake, not a custom Rust host.
`CONFIG_DIR` and `ACCOUNTS_DIR` override its default `./run/config` and
`./run/accounts` directories. Override directories must be provisioned manually;
automatic setup applies only to the defaults. It binds `127.0.0.1:3000`.
Tested on Linux. Apple Silicon macOS support is experimental and untested:
it uses the portable Linux-built Wasm components and a native Wasmtime launcher.

## Build And Test

```sh
nix develop --command make app-component
nix develop --command make test-app
nix develop --command make test
nix develop --command cargo test --locked --workspace
nix build .#authentikate-app-component
```

`make app-component` builds the service and providers, then composes
`build/app.component.wasm` using root [composition.wac](composition.wac).
`make compose-app` reuses existing service, Argon2, HMAC and stdout-email artifacts
in `build/`, rebuilding gateway, storage and config before composition.
`make test-app` composes and runs the real Wasmtime HTTP tests; build those reused
artifacts first. `make test` checks the Rocq/extraction and adapter tests.
The default `nix build` still builds the uncomposed service, not the final app.

To run the local build with the flake-pinned Wasmtime:

```sh
nix run .#wasmtime -- serve \
  --addr 127.0.0.1:3000 \
  -S cli=y,inherit-network=n,allow-ip-name-lookup=n,tcp=n,udp=n,inherit-env=n \
  --dir ./run/config::/config \
  --dir ./run/accounts::/accounts \
  --max-instance-reuse-count 1 \
  --max-instance-concurrent-reuse-count 1 \
  --max-concurrent-requests 1 \
  --max-concurrent-connections 8 \
  -W fuel=2000000000 \
  -W max-memory-size=134217728 \
  -W max-memories=8 \
  -W max-instances=32 \
  -W max-tables=16 \
  -W max-wasm-stack=8388608,async-stack-size=16777216 \
  --no-logging-prefix \
  build/app.component.wasm
```

`-S cli` enables the WASI CLI interfaces and directory preopens used by config,
storage and stdout email. `--no-logging-prefix` keeps email output as plain JSON
lines; the launcher includes this flag too. The explicit stack bounds accommodate
the extracted parser at the 16 KiB request boundary.

## Configuration

[config.example.json](config.example.json) supplies a safe printable, escape-free
issuer, token TTL, sender and loopback port-3000 authority policy. Configure
`service.issuer`, `service.token_ttl_seconds` and `service.email_from` in
`/config/config.json`; these are not environment-variable settings. Issuers must
be nonblank printable ASCII without quotes or backslashes, because the Rocq JSON
printer does not escape them. See the [config provider](components/config/README.md)
for validation rules.

Configuration is read and validated on every request, not cached at startup.
Service configuration also reads `/config/signing.key`. Stop all serving processes
before changing multiple files: separate reads are not an atomic snapshot. There
is no automatic key regeneration or rotation. Replacing the key invalidates old
tokens.

For non-loopback use, manually provision an explicit `policy.approved_origin`
(for example `https://auth.example.test`) and configure the listener/proxy and TLS
accordingly. With `approved_origin: null`, the gateway uses the listed
`approved_authorities`; update their ports if the listening port changes. The CLI
does not implement the removed host's custom non-loopback safety validation or
derive policy from its listener address. Keep the demo on loopback by default.

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
  [email](components/email) that currently writes to stdout. Secret keys stay
  outside the Rocq heap behind opaque handles.
- **Config provider:** reads provisioned JSON and the persistent signing key,
  exporting service settings to the service and origin policy to the gateway.
- **Wasmtime CLI:** serves the final component with WASI capabilities and
  resource limits. Instance reuse is disabled so each request has fresh component
  state. The custom Rust host is no longer part of the production path.

The composed artifact exports `wasi:http/incoming-handler@0.2.4`. See
[composition.wac](composition.wac) for the provider wiring. Config and storage
share the composition's WASI filesystem imports and see **all** preopens, including
both `/config` and `/accounts`. The CLI `--dir` grants are writable, not per-provider
read-only isolation. Config's implementation only reads, but it and storage are
trusted with these shared capabilities. OS permissions protect files from other
users, not from components running as the same user. The gateway has no filesystem
imports; this is an interface boundary, not separate runtime preopen sandboxing.

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
