# Identity Workbench

A local, ephemeral demonstration of the actual Rocq-generated authentication
service. `cargo run` at the repository root runs the composed Wasm component in
Wasmtime and hands it HTTP requests.

The host does not handle requests. The composed component exports
`wasi:http/incoming-handler@0.2.4`, and `components/frontend` is what routes,
applies the Host/Origin policy, serves the static assets, checks the method and
media type, enforces the body limit and read deadline, and sets the response
security headers. What is left here is the part that cannot be a per-request
component instance: the engine and its limits, admission control, the account
map, and configuration.

## Build And Run

Requires Rust >=1.97. Building components also requires the existing Rocq
toolchain, Node (build/test tooling only), Binaryen, wasm-tools, the Rust
`wasm32-unknown-unknown` target, and WAC 0.12.0 (included in the Nix development shell):

```sh
nix develop
make host-component
cargo run --locked
```

The Nix development shell provides a locked Fenix Rust toolchain including the
Wasm target, WAC and the component build tools; no rustup setup is needed.
`make compose-host` composes existing
`build/{authentikate,argon2,ed25519,email-stdout}.component.wasm` without invoking
Rocq. Both targets produce `build/host.component.wasm`. Once that exists, running
the host requires no Node, WAC, Rocq or Wasm build tools. Missing artifacts fail
startup with a build instruction; Cargo does not silently rebuild Rocq.

Open http://127.0.0.1:3000. Sign up, log in, and validate the populated token;
change a signature character and validate again to see rejection. Tokens are
not persisted in browser storage. Assets in `components/frontend/assets/` are embedded into the front-end
component at build time. All commands here run from the repository root; its `Cargo.toml`
defines a workspace with `host` as the default member. `host/Cargo.toml` defines
the host crate; the provider crates are also workspace members and share the
root lockfile and target directory.

| Environment | Default | Meaning |
| --- | --- | --- |
| `LISTEN` | `127.0.0.1:3000` | IP socket address, including port; port 0 chooses a free port |
| `PUBLIC_ORIGIN` | unset | Exact approved HTTP(S) origin for a custom authority/reverse proxy |
| `HOST_COMPONENT` | `build/host.component.wasm` | Composed component path, relative to the working directory |
| `SIGNUP_EMAIL_FROM` | `Authentikate <hello@example.test>` | Welcome-email sender |

Without `PUBLIC_ORIGIN`, only `127.0.0.1`, `localhost`, and `[::1]` Host authorities
at the actual listening port are accepted. IPv6 requires an IPv6 listener.
Non-loopback `LISTEN` requires an explicit `PUBLIC_ORIGIN`; this is an opt-in,
not production hardening. For a proxy, set for example
`PUBLIC_ORIGIN=https://demo.example.test`, preserve that Host header, and terminate
TLS at the proxy. Forwarded headers are deliberately not trusted. Supplied Origin
headers must exactly match the approved origin; missing Origin is allowed for
non-browser clients. No permissive CORS headers are emitted.

## Composition

`host/composition.wac` instantiates the existing Rust Argon2, Ed25519, stdout-email
and Rocq service components. It connects the service imports directly to those
component exports, with no host crypto implementations or forwarding callbacks.
It exports the service API and the same signer/hash instances for initialization.
It also instantiates the HTTP front-end, wiring it to the *same* Argon2 and
Ed25519 instances as the service rather than to fresh ones. That is
load-bearing: `config.key` is an instance-local Ed25519 handle, so a second
signer instance would hand the service a handle naming nothing, and
`config.dummy_params` has to be the parameters real records are enrolled under
or the missing-account login path becomes distinguishable by duration. The
composition now enforces this, where the host previously relied on exporting
the right instances and being asked for them in the right order. The crypto
interfaces are consequently no longer re-exported to the host.

`host/world.wit` describes this host-facing surface; bindings use the authoritative
service, crypto and keyvalue WIT sources, staged by `host/build.rs`.

The host generates a random signing seed once per process and passes it, with
the issuer, TTL, welcome-email sender and origin policy, through
`authentikate:frontend/settings@0.1.0` -- a typed six-field record rather than a
grant of `wasi:cli/environment`, which would be a capability to read every
variable in the process. The front-end provisions the seed into the Ed25519
component via `import-key` once per request and passes the returned handle to
the service; public-key derivation, signing and verification all remain inside
the Ed25519 component. One honest consequence of removing the host's call site:
the seed now crosses into the front-end guest as well as the Ed25519 one.

The missing-account dummy tag is a fixed 32 bytes rather than a derived hash.
Only the cost parameters affect how long the absent path takes -- the tag enters
only the final constant-time comparison -- and `login_check` in `Api.v` returns
`Unauthorized` whenever the lookup found nothing regardless of what the hash
said. The parameters come from the Argon2 component's `recommended-params`.
Enrollment salts come from WASI random inside that component.

The host provides only WASI clock/random, stdout/I/O, an in-memory WASI keyvalue
resource table, and `settings`. It rejects composed artifacts with unexpected
imports, including unresolved crypto imports. No guest filesystem, environment,
or network access is granted, and there is no outbound HTTP: `wasmtime-wasi-http`
is built without `default-send-request` and the host's `send_request` refuses
with `HttpRequestDenied`.

Each request gets a fresh composed instance to reclaim the Rocq bump heap. The
response is taken from the component while the guest is still running, because
the guest writes its body into a bounded channel and would block if nothing
drained it; the instance is dropped once the body is fully written, so the
admission permit is held until then. Responses are framed with
`Transfer-Encoding: chunked`, since the length is not known when the response
head is sent. Only one request executes at a time; up to eight admitted requests (including the
active request) may wait/run, with excess returning 503. The permit stays held
through blocking component execution even if the HTTP request is cancelled.
Signup does not depend on this serialization: it creates the record through
the `wasi:keyvalue/atomics` compare-and-swap, which this host performs under
one mutex over its account map.
Wasmtime fuel is limited to two billion per instance and linear memories to
128 MiB each (at most eight), with instance/table count limits as well. Fuel is
an instruction budget, not a wall-clock deadline or full process memory limit.
Bodies are capped at 16 KiB, including chunked requests, with a 15-second body
read deadline. Static paths are allowlisted and use a restrictive CSP.

Signup writes one JSON welcome email to stdout after the account write succeeds.
Only sender, recipient and welcome text are logged, never passwords or hashes.
An email-write failure returns 500 but leaves the account stored: retry returns
409 and login still works. Success means stdout accepted the write, not delivery.
Startup diagnostics go to stderr. The issuer is `demo`; token TTL is 600 seconds.

## Tests And Limits

```sh
make compose-host
cargo fmt --check
cargo check --locked
cargo test --locked
```

Tests require the real composed artifact and fail if it is missing or broken.
They cover signup/login/validate across fresh instances, claims, signature
tampering, wrong/missing accounts, concurrent duplicate signup, malformed JSON,
Host/Origin and absolute-target rejection, JSON media type, 16 KiB limits,
chunked socket requests, assets, bounded admission, and actual stdout emails.
On Linux, `/dev/full` tests an actual stdout failure and the surviving account.
The in-crate tests drive `serve` directly with a non-streaming body, so they
exercise admission and a real instance without a socket; `host/tests/http.rs`
goes over a real TCP connection. `absent_account_still_pays_for_argon2` is the
measurement that guards the missing-account dummy hash against being optimized
away -- nothing in the proofs rules that out. The front-end's own routing,
media-type and origin checks are unit-tested natively with
`cargo test -p authentikate-frontend`, no engine required.

Accounts and the signing seed are process-local and lost on restart. There is
no durable storage, TLS, recovery, rate limiting, distributed uniqueness or
security/timing proof for the whole service. Welcome emails expose recipient
addresses on stdout. Keep this demo on loopback unless deliberately testing a
controlled proxy. Node remains only for component build/adapter/email tests;
the Nix development shell includes JCO for the email component tests.
