Written by LLMs. TODO: check.

# Identity Workbench

A local demonstration of the actual Rocq-generated authentication
service. `cargo run` at the repository root runs the composed Wasm component in
Wasmtime and hands it HTTP requests.

The host bridges socket HTTP to the component rather than implementing application
routes. The composed component exports `wasi:http/handler@0.3.0`, and
`components/gateway` is what routes,
applies the Host/Origin policy, serves the static assets, checks the method and
media type, enforces the body limit and read deadline, and sets the response
security headers. What is left here is the part that cannot be a per-request
component instance: the engine and its limits, admission control, the storage
directory preopen, and configuration. Accounts persist; the signing key is ephemeral.

## Build And Run

Requires Rust >=1.97. Building components also requires the existing Rocq
toolchain, Node (build/test tooling only), Binaryen, wasm-tools with component-model
async support, the Rust `wasm32-unknown-unknown` target, and WAC 0.12.0 (included
in the Nix development shell):

```sh
nix develop
make host-component
cargo run --locked
```

The Nix development shell provides a locked Fenix Rust toolchain including the
Wasm target, WAC and the component build tools; no rustup setup is needed.
The current Nix lock supplies wasm-tools 1.261.0 and WAC 0.12.0, checked with
the p3 composition and `wasm-tools validate --features cm-async`. Both
`make gateway-component` and `make compose-host` enable async validation.
The gateway uses wit-bindgen 0.57.1 with `async-spawn` and `futures` 0.3;
the other Rust guests retain wit-bindgen 0.46, resolved together by `Cargo.lock`.
`make compose-host` composes existing
`build/{authentikate,argon2,hmac,email-stdout}.component.wasm` without invoking
Rocq, rebuilding the gateway and storage providers. Both targets produce `build/host.component.wasm`. Once that exists, running
the host requires no Node, WAC, Rocq or Wasm build tools. Missing artifacts fail
startup with a build instruction; Cargo does not silently rebuild Rocq.

Open http://127.0.0.1:3000. Sign up, log in, and validate the populated token;
change a signature character and validate again to see rejection. Tokens are
not persisted in browser storage. Assets in `components/gateway/assets/` are embedded into the gateway
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
| `STORAGE_DIR` | `accounts` | Persistent account directory, mounted in the storage component at `/accounts` |

Without `PUBLIC_ORIGIN`, only `127.0.0.1`, `localhost`, and `[::1]` Host authorities
at the actual listening port are accepted. IPv6 requires an IPv6 listener.
Non-loopback `LISTEN` requires an explicit `PUBLIC_ORIGIN`; this is an opt-in,
not production hardening. For a proxy, set for example
`PUBLIC_ORIGIN=https://demo.example.test`, preserve that Host header, and terminate
TLS at the proxy. Forwarded headers are deliberately not trusted. Supplied Origin
headers must exactly match the approved origin; missing Origin is allowed for
non-browser clients. No permissive CORS headers are emitted.

## Composition

`host/composition.wac` instantiates the existing Rust Argon2, HMAC-SHA-256, stdout-email, storage
and Rocq service components. It connects the service imports directly to those
component exports, with no host crypto implementations or forwarding callbacks.
It also instantiates the HTTP gateway, which gets the service export and
nothing else from inside the composition: no crypto instances to wire, because
it no longer assembles the service's configuration.

`host/world.wit` describes this host-facing surface; bindings use the authoritative
config, service `api` and accounts WIT sources, staged by `host/build.rs`.

The host generates a random signing seed once per process and hands out its
configuration through two interfaces rather than one.
`authentikate:config/service@0.1.0` carries the seed, the issuer, the TTL and
the welcome-email sender, and is imported only by the service's world;
`authentikate:config/policy@0.1.0` carries the approved origin or the bound
authorities, and is imported only by the gateway. The host answers both, so it
is the only place the two meet. The split is a capability boundary: the
gateway terminates HTTP and is the component an attacker talks to, and it has
no import through which the seed could arrive. Neither interface is a grant of
`wasi:cli/environment`, which would be read access to every variable in the
process.

The service's adapter reads `config/service` once per request and does the rest
itself: `hmac.import-key` on the shared secret, and `argon2.recommended-params`
for the cost parameters. Both HMAC generation and verification use the same
opaque handle; there is no public-key derivation. Handles are
instance-local and an instance is per-request, so the import repeats; what does
change is that the gateway never holds the key. Signing and verification stay
inside the HMAC-SHA-256 component throughout. A key HMAC-SHA-256 refuses is a
`500 {"error":"Service is misconfigured"}` built in the adapter -- byte for
byte what the gateway used to return -- rather than a trap, which would lose
the body; `a_rejected_signing_key_is_a_clean_500` and `tests/component.mjs`
both pin it.

The missing-account dummy record is built in the adapter too: a fixed 16-byte
salt and a zero-filled tag whose length follows `recommended-params`. Only the
cost parameters affect how long the absent path takes -- the tag enters only
the final constant-time comparison -- and `login_check` in `Api.v` returns
`Unauthorized` whenever the lookup found nothing regardless of what the hash
said. Enrollment salts come from WASI random inside the Argon2 component.

The Wasmtime 50 host enables component-model async execution and links p3 HTTP
and clocks for the gateway alongside p2 WASI (linked asynchronously) for the existing
providers (clock/random, stdout/I/O and a dedicated storage directory preopen).
The gateway's service and policy imports remain synchronous. The host also
supplies the two configuration interfaces. It rejects composed artifacts with unexpected
imports, including unresolved crypto and accounts imports. Filesystem access is
restricted to `STORAGE_DIR`; no environment or network access is granted, and there is no outbound HTTP: `wasmtime-wasi-http`
is built without `default-send-request` and the host's `send_request` refuses
with `HttpRequestDenied`.

Wasmtime 50 labels its p3 support experimental, unstable, and not production-ready.

Each request gets a fresh composed instance to reclaim the Rocq bump heap.
The host bridges Hyper requests to p3 requests and uses `Store::run_concurrent`
to drive the async handler, body streams/futures and request I/O together.
It collects the response body with a 1 MiB limit before returning the response
to Hyper, rather than streaming it to the socket; the returned body has a known
length. A component failure, response-read error or response over that limit
produces a host-level 500.

Execution runs in `spawn_blocking`, using the Tokio runtime handle to drive
async I/O, so synchronous providers such as Argon2 do not occupy Tokio's I/O
workers. Only one request executes at a time; up to eight admitted requests
(including the active request) may wait/run, with excess returning 503.
The execution and admission permits remain held until request I/O and response
collection finish and the instance is dropped, even if the HTTP request is
cancelled. The permits do not cover subsequent socket transmission of the
buffered response.
Signup does not depend on this serialization: it creates the record through
the `authentikate:storage/accounts.create` primitive, which the storage component implements
by writing and syncing a complete temporary record, then atomically hard-linking
it to its final hashed path. This works across processes, not just one host.
Wasmtime fuel is limited to two billion per instance and linear memories to
128 MiB each (at most eight), with instance/table count limits as well. Fuel is
an instruction budget, not a wall-clock deadline or full process memory limit.
Request bodies are capped at 16 KiB, including chunked requests, with a single
15-second read deadline covering both the body stream and final trailers result.
The gateway returns 413 for oversize bodies, 408 for deadline expiry, and 400 for
transfer errors or cancelled reads. Static paths are allowlisted and use a
restrictive CSP.

The 16 KiB cap is a transport ceiling, not a guarantee that every smaller JSON
input fits the extracted parser's call stack. Valid JSON padded with trailing
whitespace to that ceiling can exhaust the Wasm call stack and return a host-level 500.

Signup writes one JSON welcome email to stdout after the account write succeeds.
Only sender, recipient and welcome text are logged, never passwords or hashes.
An email-write failure returns 500 but leaves the account stored: retry returns
409 and login still works. Success means stdout accepted the write, not delivery.
Startup diagnostics go to stderr. The issuer is `authentikate`; token TTL is 600 seconds.

## Tests And Limits

```sh
make compose-host
cargo fmt --check
cargo check --locked
cargo test --locked
cargo test --locked -p authentikate-gateway
```

Tests require the real composed artifact and fail if it is missing or broken.
They cover signup/login/validate across fresh instances, claims, signature
tampering, wrong/missing accounts, concurrent duplicate signup, malformed JSON,
Host/Origin and absolute-target rejection, JSON media type, 16 KiB limits,
chunked socket requests, assets, bounded admission, and actual stdout emails.
On Linux, `/dev/full` tests an actual stdout failure and the surviving account.
Storage tests drive the actual Wasm provider, including two-process contention,
fresh-instance persistence, complete concurrent reads, corruption, and rejected
overwrites. HTTP tests restart the host and confirm accounts survive while old
tokens stop validating because the signing seed changes.
The in-crate tests drive `serve` directly with a non-streaming body, so they
exercise admission and a real instance without a socket; `host/tests/http.rs`
goes over a real TCP connection. `absent_account_still_pays_for_argon2` is the
measurement that guards the missing-account dummy hash against being optimized
away -- nothing in the proofs rules that out. The gateway's own routing,
media-type and origin checks are unit-tested natively with
`cargo test -p authentikate-gateway`, no engine required.

Accounts persist in `STORAGE_DIR`; the signing seed is lost on restart, so old
tokens stop validating. New directories use mode 0700 on Unix; operators must
protect existing directories. Storage relies on filesystem hard links and sync;
see [the storage README](../components/storage/README.md) for durability and
orphan-temporary cleanup limits. There is no TLS, recovery tooling, rate limiting,
or security/timing proof for the whole service. Welcome emails expose recipient
addresses on stdout. Keep this demo on loopback unless deliberately testing a
controlled proxy. Node remains only for component build/adapter/email tests;
the Nix development shell includes JCO for the email component tests.
