# Identity Workbench

A local, ephemeral demonstration of the actual generated service component, not a replacement authentication implementation. Request parsing and authentication decisions run in the Rocq-generated component.

## Run

Requires Node 24.7 or newer with `node:crypto.argon2Sync`, npm, and both compiled artifacts: `build/authentikate.component.wasm` (rebuilt with the email sender import and `email-from` configuration) and `build/email-stdout.component.wasm`. Build the latter with `make email-stdout-component` using the parent's Rust/Wasm toolchain, or `make test-email-stdout` to build and test it.

```sh
npm install
npm run dev
```

Open http://127.0.0.1:3000. Startup transpiles both components with jco into `build/web-component` and compiles the resulting core modules. The service's email import is mapped to the actual stdout component's exported sender, not a JavaScript email implementation. No Nix or Wasm toolchain is needed once both components are built. `PORT` overrides 3000; `HOST` overrides the loopback-only binding default, which should be retained for this demo. Only `127.0.0.1`, `localhost`, and `[::1]` Host authorities at the actual listening port are accepted, even if `HOST` is overridden. IPv6 access additionally requires an IPv6 listener. Custom domains and reverse proxies are intentionally unsupported.

Create an account using a test email and password, enter the same password in Log in, then validate the automatically populated token. Change a token character and validate again to see rejection. The response journal shows only response data, never the submitted password. Tokens are not persisted in browser storage.

Successful signup writes one JSON welcome email to process stdout after the account write is acknowledged. `SIGNUP_EMAIL_FROM` overrides `Authentikate <hello@example.test>`; the subject is `Welcome to Authentikate` and the text is `Your Authentikate account has been created.` The sole recipient is the account email; messages are plain text and the idempotency key is absent. There is no native email SDK, network delivery, or email retry. A reported email write failure returns 500 but leaves the account stored: repeating signup returns 409 and login still works. Node stdout writes can be buffered; success means the host accepted the write, not durable delivery.

```sh
npm run test:web
```

The integration test starts the real server on an ephemeral loopback port and exercises signup, duplicate signup (including concurrent requests), login, password rejection, signature validation and returned claims, malformed input, HTTP limits, and Host/Origin rejection. It captures the full actual stdout email, checks that no password is included and only successful new signups send, and injects a stdout write failure to verify 500, then 409 and successful login for the stored account. It deliberately fails if either generated component is broken, stale, or missing.

## Boundaries

- Every service request gets fresh service and stdout email component instances, bounding the lifetime of their Wasm heaps. Compiled modules are reused.
- The WASI keyvalue provider implements `Bucket` and `open` over a server-local Map. Records are password hashes with random salts, not plaintext passwords.
- In this single Node process, component calls and Map operations are synchronous, so concurrent duplicate signups are serialized: one succeeds with 201 and the other receives 409. This is not a transactional uniqueness guarantee for a future asynchronous store or multiple server processes. Production persistence would require an atomic insert/unique constraint; this demo supplies neither a distributed store nor production concurrency guarantees.
- Enrollment uses native Argon2id with 19,456 KiB, two iterations, one lane, a 32-byte tag, and 16 random salt bytes. The provider rejects excessive costs before derivation. The missing-account dummy tag is also derived with real native Argon2.
- The server generates one Ed25519 key pair at startup. Private-key handle 1 stays host-side; configuration contains only its raw 32-byte public key. The issuer is `demo` and token TTL is 600 seconds.
- Restarting loses accounts and the signing key. There is no production persistence, TLS, account recovery, rate limiting, or deployment hardening. Native synchronous hashing blocks Node's event loop; this is not an internet-facing server.
- API requests must be JSON, are limited to 16 KiB, and receive no permissive CORS headers. All requests must use an allowed loopback Host and an origin-form relative request target; supplied API Origin headers must match that approved authority. This blocks the matching-Host-and-Origin DNS-rebinding case, but is not authentication or a substitute for network isolation. Keep the listener on loopback. Static assets use an explicit allowlist and a restrictive content security policy. Welcome emails log recipient addresses and message content to stdout; request bodies, tokens, passwords, and keys are not logged.
