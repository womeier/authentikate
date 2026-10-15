# Authentikate — plan

A small authentication backend whose request handling is written in Rocq,
compiled to WebAssembly by CertiRocq, and run under Node.  Cryptography is
not written in Rocq: the Wasm module calls out to a Rust crypto library
through imports.

This is a working draft, meant to be refined.

## The service

Two endpoints, JSON in and JSON out.

| Method | Path            | Request                        | Response                     |
| ------ | --------------- | ------------------------------ | ---------------------------- |
| `POST` | `/login`        | `{ email, password }`          | `{ token }` (a JWT)          |
| `POST` | `/validate`     | `{ token }`                    | `{ valid, claims? }`         |

- `/login` looks the user up, checks the password against a stored hash, and
  on success mints a JWT.  Wrong credentials: `401`, no detail about which
  half was wrong.
- `/validate` verifies the token's signature and its `exp`, and reports
  whether it is good.  A bad token is a `200` with `valid: false` rather than
  an error — it is a question, not a failure.

JWT shape: compact JWS, `HS256` to start (one symmetric key, simplest thing
that can be made to work), with `EdDSA`/Ed25519 as the next step once the
FFI carries more than one primitive.  Claims: `sub`, `iat`, `exp`, and an
`iss` naming the service.

## Layers

```
   HTTP  ──▶  Node wrapper  ──▶  Wasm module (CertiRocq)  ──▶  crypto imports
             (server, JSON        (routing, JWT encode/        (Rust: HACL*,
              bytes in/out)        decode, claim checks)        libcrux, or
                                                                boringssl)
```

The split: everything that is a decision lives in Rocq, everything that is a
primitive lives in Rust, and Node is only a transport.

### Rocq (`theories/`)

- `Bytes.v` — byte strings and the small amount of arithmetic the encodings
  need.
- `Base64.v` — base64url without padding, encode and decode, with a
  round-trip proof.
- `Json.v` — enough JSON to read a two-field request object and write a
  two-field response.  A parser on bytes, total, returning an option.
- `Jwt.v` — the compact JWS: split on `.`, decode the halves, check the
  header, hand the signing input to the FFI, compare the tag.
- `Claims.v` — `exp`/`iat` checks against a clock the host supplies.
- `Crypto.v` — the FFI surface, as axioms: `hmac_sha256`, `sha256`,
  `verify_password`, `random_bytes`.  Nothing below this line is proved; it
  is where trust is placed, deliberately and in one place.
- `Api.v` — `handle : request -> response`, a pure function.  This is the
  whole service.
- `Proofs.v` — what is actually established (see below).
- `extraction.v` — one record of entry points, `CertiRocq Compile Wasm`.

### Node wrapper (`host/`)

An HTTP server that reads the body, writes it into the module's linear
memory as a Rocq value, calls `handle`, reads the result back, and replies.
It also supplies the imports the module asks for, forwarding them to the
Rust library.  Value marshalling follows the CertiRocq representation
(immediates, blocks, closures) — the raytracer's `src/index.js` is the
worked example to crib from.

### Rust crypto (`crypto/`)

A `cdylib`/Wasm-side shim exposing the four primitives above over a flat
byte-pointer interface, backed by one of HACL*, libcrux, or BoringSSL.
Decision deferred; libcrux is the first candidate since it is itself
verified and ships a Wasm-friendly build.

Two possible linkages, to be settled by experiment:

1. **Host imports** — the Rust code is a native Node addon (or `wasm` module
   loaded alongside), and the crypto imports are satisfied by JS functions
   that call it.  Simple, and the obvious first target.
2. **Wasm-to-Wasm linking** — the Rust crypto is compiled to Wasm and linked
   with the CertiRocq module (component model, or a manual two-module
   instantiation sharing a memory).  Cleaner story, more plumbing.

## Spec and client

- `openapi.yaml` at the root, hand-written, the source of truth for the two
  endpoints.
- A generated client checked into `client/`, from `openapi-generator` (or
  `oapi-codegen`-style generation pinned in the flake so the output is
  reproducible).  Target language to pick: TypeScript is the path of least
  resistance given the Node host.
- A `nix run .#gen-client` that regenerates it, and a check that the checked-in
  client matches what the generator produces.

## What gets proved

Worth being honest about the boundary.  Proved:

- base64url round-trips.
- The JWT encoder and decoder are inverse: a token minted by `sign` is
  accepted by `verify` under the same key, and the claims that come out are
  the claims that went in.
- `verify` rejects a token whose signing input does not match its tag, given
  only that the FFI's MAC is a function (no cryptographic assumption needed
  for this direction).
- `handle` never returns a token on a failed credential check — the property
  the service exists for.

Assumed: the primitives in `Crypto.v` behave as their names say.  The point
of the exercise is that the assumption set is four axioms wide and written
down.

## Open questions

- **Does CertiRocq's Wasm backend emit imports for axioms?**  The whole FFI
  plan rests on this.  If it does not, the fallback is to thread the crypto
  results in as arguments: the host computes the MAC first and passes it
  alongside the token, which costs a round trip per request and some of the
  elegance, but works with the backend as it is.  Check this early — it
  decides the shape of `Crypto.v` and of the host.
- Where do users live?  An in-memory table in the Rocq module is enough to
  start; a real store means more FFI.
- Clock: an import, or an argument to `handle`?  An argument keeps `handle`
  pure and makes the `exp` proofs trivial, and is probably right.
- Key management: for now a literal in the host, passed in at
  instantiation.

## Steps

1. ~~Nix flake with Rocq 9.1 and CertiRocq.~~
2. Settle the FFI question with the smallest possible experiment: one axiom,
   one import, one call.
3. `Base64.v` and `Json.v` with their proofs — no crypto needed, and they are
   the bulk of the byte-level work.
4. `Jwt.v` against a stub MAC, plus the round-trip proof.
5. The Node host: marshalling, then the HTTP surface.
6. Swap the stub for the Rust library.
7. `openapi.yaml` and the generated client.
