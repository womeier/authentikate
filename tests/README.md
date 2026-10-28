# Runtime HTTP Tests

From the repository root, after building `build/app.component.wasm`, run:

```sh
node --test tests/http.mjs
```

Only Node built-ins are used. A recent Wasmtime CLI with `serve` and WASI HTTP
0.2.4 support must be on `PATH`. Alternatively:

```sh
nix shell .#wasmtime --command node --test tests/http.mjs
WASMTIME=/absolute/path/to/wasmtime APP_COMPONENT=build/app.component.wasm node --test tests/http.mjs
```

`WASMTIME` is a binary path/name, not a shell command. `APP_COMPONENT` defaults to
`build/app.component.wasm`; relative component paths resolve against the repository
root, independent of the invocation directory. Missing prerequisites are failures,
not skipped tests. The `/dev/full` email-failure test is Linux-only.

Each server runs the real `wasmtime serve` command with an explicitly selected
ephemeral IPv4 loopback port, WASI CLI with network/environment inheritance disabled,
no logging prefix, one request per instance,
one concurrent request, eight concurrent connections, and these limits:

```text
-W fuel=2000000000,max-memory-size=134217728,max-memories=8,max-instances=32,max-tables=16
-W max-wasm-stack=8388608,async-stack-size=16777216
--dir accounts::/accounts --dir config::/config
```

The process working directory is a private temporary directory (0700), containing
private accounts/config directories and provisioned config/key files (0600). Each
fixture gets a random exact-32-byte signing key; restart tests retain both that key
and accounts. Cleanup stops child processes and removes fixtures even on assertion
failure. Port selection closes a temporary listener before spawning Wasmtime, so a
small OS port-allocation race remains; startup errors are reported, not ignored.

Coverage includes real HTTP routing and headers, authority/port and Origin policy,
malformed request targets, fixed-length and multi-chunk body limits, signup/login/
validate and duplicates, stdout email and delivery failure, wrong/unknown passwords,
custom issuer/TTL/sender, independent Node HS256 signing and verification, rejected
tampered/expired/wrong-issuer tokens, persistence across process restarts,
and fail-closed missing/malformed keys and configuration. Invalid provisioning must
produce HTTP 500 without account creation or email; connection failures do not count
as successful fail-closed assertions. This suite does not use the old Rust host or
the Wasmtime Rust library.

`tests/app-interface.mjs` runs during composition and checks the exact external
WASI import/export allowlist, rejecting unresolved custom imports and unintended
network or environment capabilities.
