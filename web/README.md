# Identity Workbench

A local, ephemeral demonstration of the actual generated service component, not a replacement authentication implementation. Request parsing and authentication decisions run in the Rocq-generated component.

## Run

Requires Node 24.7 or newer with `node:crypto.argon2Sync`, npm, and the parent's existing `build/authentikate.component.wasm` artifact.

```sh
npm install
npm run dev
```

Open http://127.0.0.1:3000. Startup transpiles the component with jco into `build/web-component`, maps its three host interfaces, and compiles the resulting core modules. No Nix or Wasm toolchain is needed once the parent component is built. `PORT` overrides 3000; `HOST` overrides the loopback-only binding default, which should be retained for this demo. Only `127.0.0.1`, `localhost`, and `[::1]` Host authorities at the actual listening port are accepted, even if `HOST` is overridden. IPv6 access additionally requires an IPv6 listener. Custom domains and reverse proxies are intentionally unsupported.

Create an account using a test email and password, enter the same password in Log in, then validate the automatically populated token. Change a token character and validate again to see rejection. The response journal shows only response data, never the submitted password. Tokens are not persisted in browser storage.

```sh
npm run test:web
```

The integration test starts the real server on an ephemeral loopback port and exercises signup, duplicate signup (including concurrent requests), login, password rejection, signature validation and returned claims, malformed input, HTTP limits, and Host/Origin rejection. It deliberately fails if the generated component is broken or missing.

## Boundaries

- Every service request gets a fresh component instance, bounding the lifetime of its bump-allocated Wasm heap. Compiled modules are reused.
- The WASI keyvalue provider implements `Bucket` and `open` over a server-local Map. Records are password hashes with random salts, not plaintext passwords.
- In this single Node process, component calls and Map operations are synchronous, so concurrent duplicate signups are serialized: one succeeds with 201 and the other receives 409. This is not a transactional uniqueness guarantee for a future asynchronous store or multiple server processes. Production persistence would require an atomic insert/unique constraint; this demo supplies neither a distributed store nor production concurrency guarantees.
- Enrollment uses native Argon2id with 19,456 KiB, two iterations, one lane, a 32-byte tag, and 16 random salt bytes. The provider rejects excessive costs before derivation. The missing-account dummy tag is also derived with real native Argon2.
- The server generates one Ed25519 key pair at startup. Private-key handle 1 stays host-side; configuration contains only its raw 32-byte public key. The issuer is `demo` and token TTL is 600 seconds.
- Restarting loses accounts and the signing key. There is no production persistence, TLS, account recovery, rate limiting, or deployment hardening. Native synchronous hashing blocks Node's event loop; this is not an internet-facing server.
- API requests must be JSON, are limited to 16 KiB, and receive no permissive CORS headers. All requests must use an allowed loopback Host and an origin-form relative request target; supplied API Origin headers must match that approved authority. This blocks the matching-Host-and-Origin DNS-rebinding case, but is not authentication or a substitute for network isolation. Keep the listener on loopback. Static assets use an explicit allowlist and a restrictive content security policy. Request bodies, tokens, passwords, and keys are not logged.
