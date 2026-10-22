# Authentikate Plan

An authentication backend with signup, login and JWT validation written in Rocq,
compiled to WebAssembly by CertiRocq, and composed with Rust providers using WAC.
The proofs describe the pure authentication logic under explicit provider
assumptions. They do not establish end-to-end implementation security or
whole-service constant-time behavior.

This document records the current design, verification boundary and priorities.
Build/run instructions live in [README.md](README.md) and
[host/README.md](host/README.md); detailed pending tasks live in [TODO.md](TODO.md).

## Current Architecture

```text
HTTP client
    |
Rust host: Wasmtime, admission control, configuration, capabilities
    |
Rust gateway: HTTP policy, routing, assets, body limits, response headers
    |
Rocq service: parsing, authentication, account records, JWT claims
    |
    +-- Argon2: password enrollment and verification
    +-- HMAC: HS256 tag generation and verification
    +-- Accounts: opaque get / atomic create-if-absent
    +-- Email: welcome notification, currently stdout
```

[host/composition.wac](host/composition.wac) connects the service directly to
these providers. The composed artifact exports
`wasi:http/incoming-handler@0.2.4`; the service alone exports
`authentikate:service/api@0.1.0`, taking body bytes and returning status/body.

Each HTTP request gets a fresh composition, reclaiming the Rocq bump heap and
provider state. Account files outlive instances. The host's HMAC key survives
requests but not a process restart, so existing tokens stop validating after
restart while accounts remain usable.

The gateway imports the service API and origin-policy configuration, not the
HMAC key or filesystem. The service's adapter reads its own configuration and
imports the shared key into the crypto component. Only opaque key handles enter
the Rocq heap. The provisioning host and ABI marshalling still handle key copies.

## Request Behavior

| Method | Path | Request | Successful Response |
| --- | --- | --- | --- |
| POST | `/api/signup` | `{email, password}` | `201 {}` |
| POST | `/api/login` | `{email, password}` | `200 {token}` |
| POST | `/api/validate` | `{token}` | `200 {valid, claims?}` |

Signup checks the raw key, enrolls the password, constructs and validates the
account record in Rocq, atomically creates it, then sends a welcome email.
An existing key or lost create race returns `409`. Storage, enrollment and
email failures return `500`. Email acceptance is not delivery; a send failure
does not roll back the account, so a retry can return `409`.

Login returns `401` for wrong credentials or an absent account, with the same
response value. Missing accounts still pay for a dummy Argon2 computation.
Storage refusal and signing failure can return `500`.

Validation checks the MAC, issuer and expiry before returning claims. An invalid
token returns `200 {valid:false}`. It never reads account storage: account changes
cannot revoke tokens, and validation does not depend on storage availability.

The JSON contract is deliberately restricted: printable ASCII strings without
escapes, non-negative integers, booleans and objects, with no duplicate keys.
Arrays, null, floats and negative numbers are rejected. See the main README for
the complete input restrictions.

## Token Cryptography

JWTs use compact JWS with HS256, a 256-bit random shared key and the full
32-byte HMAC-SHA-256 tag. Claims are `sub`, `iss`, `iat` and `exp`.

The verifier compares the encoded header against the exact HS256 header it
issues. It does not select an algorithm from token input. `none`, EdDSA and
other headers are rejected before MAC verification, even if accompanied by a
correct HMAC. Equivalent HS256 headers with different serialization are also
rejected. There is no legacy-algorithm compatibility path.

[components/crypto/hmac](components/crypto/hmac) uses pinned `libcrux-hmac`
0.0.9 and `subtle` constant-time equality. It exposes import, generation and
verification using instance-local opaque handles; it imports no host interfaces.
Both operations need the same secret, so any independent verifier can also
mint tokens. The service-only issuance assumption requires protecting that key
and not provisioning it to other issuers.

Libcrux's HACL*-origin primitive verification does not automatically cover our
wrapper, tag comparison, compilation to Wasm, or runtime side channels. Imported
and stored key buffers are zeroized, but host/ABI copies and internal library
temporaries are not guaranteed wiped.

[components/crypto/argon2](components/crypto/argon2) uses RustCrypto Argon2id.
Enrollment obtains fresh salts from WASI random and returns public encoded
salt/tag fields and cost parameters. Rocq constructs the stored JSON; raw key
bytes and secret-tag comparison remain outside the Rocq heap's computation.

## Account Storage

The custom [accounts interface](wit/accounts.wit) exposes only `get` and atomic
`create`. There are no buckets, CAS handles, overwrites or deletes. It directly
matches the Rocq abstraction in [Store.v](components/service/theories/Store.v):

```coq
kv_get    : bytes -> option (option bytes)
kv_create : bytes -> bytes -> option bool
```

For reads, `None` means failure, `Some None` absence, and `Some (Some value)` a
stored value. For creation, `None` means failure, `Some false` an existing key
or lost race, and `Some true` this caller creating the record. Failures must not
be collapsed into absence or conflict.

The Rust [storage component](components/storage/README.md) stores immutable files
under the `/accounts` preopen, backed by `STORAGE_DIR`. Filenames hash the exact
key bytes; a versioned envelope includes the original key to detect mismatches.
The value is opaque to storage and decoded by Rocq.

Creation writes and syncs a complete random exclusive temporary, then publishes
it with a hard link and syncs the directory. The link is the atomic claim and
publication point: another process cannot replace an existing account, and
readers do not see partial records. This relies on filesystem semantics, not a
proof of the provider. Post-publication sync failure leaves an account with
uncertain durability; interrupted attempts can leave ignored temporary files.
Cleanup and operational constraints are documented in the storage README.

## Rocq And Extraction

The theories in [components/service/theories](components/service/theories) cover
bytes/base64, restricted JSON, account records, JWTs, request handling and proofs.
Crypto, storage and email are passed as records of operations. Theorems state
their provider assumptions explicitly instead of importing foreign axioms.

`Secret.t` is sealed: after sealing, Rocq code cannot inspect it or convert it
back to bytes. `Key.t` holds only an opaque crypto-component handle. This is a
source-level discipline, not a timing guarantee for parsing or execution.

Eight registrations in `extraction.v` bind the operations to hand-written Wasm
adapters. The adapters translate Rocq heap values to the canonical ABI, grow
memory, restore heap alignment, marshal configuration and call extracted
closures. `Secret.of_bytes` is a registered identity because the seal is opaque
to extraction too.

The compiler boundary, hand-written adapters, internal `wasm-merge` assembly,
component tooling and execution engine remain outside the service proofs.
See [README.md's trusted computing base](README.md#trusted-computing-base) for
the inventory and adapter source comments for representation details.

## Proof Guarantees

These are statements about the pure Rocq functions, not the entire deployed
artifact. Full statements and hypotheses are in
[Proofs.v](components/service/theories/Proofs.v).

| Property | Main Result | Boundary Or Assumptions |
| --- | --- | --- |
| A login token requires a matching account and successful password verification | `no_token_without_verify`, `token_names_stored_email` | Structural; operations are arbitrary parameters |
| Unapproved JWT headers are rejected | `alg_is_pinned`, `alg_none_is_rejected` | Exact header comparison in Rocq |
| Accepted claims satisfy issuer and freshness checks | Validation lemmas | Relative to configured issuer and supplied clock |
| Signup success requires successful creation and email acceptance | `created_requires_persistence` | Checks acknowledgments, not provider honesty or delivery |
| Login hides account existence in the response value | `login_hides_existence` | Rejected credentials; storage refusal is excluded; not a timing claim |
| Validation ignores account storage | `validate_ignores_the_store` | Structural; also excludes storage-based revocation |
| Minted tokens validate before expiry | `login_then_validate` | MAC correctness, printable issuer and serialization bounds |
| Accepted tokens correspond to authenticated claims | `accepted_implies_authenticated` | Signing oracle and printable issuer |
| Forged tokens cannot validate for unauthenticated accounts | `no_valid_token_without_a_password`, `no_valid_token_for_an_unauthenticated_account` | Signing oracle and stated credential hypotheses |
| Successful signup can log in and validate | `signup_then_validate` | Argon2/MAC correctness, signing availability, storage promises and bounds |
| Two related signups cannot both create the same email | `signup_happens_once` | Create exclusivity from `store_creates` |
| Stored records and response claims survive serialization | `enrollment_record_decode`, `render_parses`, `validated_claims_reach_the_client` | Restricted JSON well-formedness and numeric bounds |

The important provider hypotheses are:

- `crypto_spec`: a generated MAC verifies under the same key handle. This is
  correctness, not unforgeability.
- `signing_oracle`: verification accepts only messages satisfying the chosen
  `signed` predicate, instantiated with this service's authenticated `minted`
  messages. This is an idealized security hypothesis, not a probabilistic HMAC
  security reduction or a proof of key custody.
- `argon2_spec`: an enrolled record verifies with the password used to create it.
- `store_creates`: successful creation is returned by a subsequent read
  (`create_then_get`), and another creation cannot also succeed
  (`create_is_exclusive`). Two operation records represent the related calls;
  the model has no mutable-state or concurrent-execution semantics.

`Print Assumptions` reports the main theorems closed under the global context.
That means the hypotheses are explicit, not that external promises disappear.
Storage durability, runtime correctness, entropy and an accurate clock remain
trusted. JSON round trips require printable escape-free strings, distinct keys,
numbers below `10^32` and a value fuel measure within the parser's budget of 16.

## Timing And Operational Limits

No whole-service constant-time property is established. Password parsing,
pointer-chased bytestrings, allocation, storage behavior, providers and the JIT
remain possible timing channels. Argon2id itself has password-dependent memory
accesses. Source-level secret opacity and constant-time tag comparison do not
prove executable timing behavior.

Dummy hashing mitigates the obvious absent-account fast path. It uses one cost
parameter set; mixed generations of stored Argon2 costs remain distinguishable.
Rehash-on-login and a migration policy are not implemented. The absent-account
timing regression is evidence against eliminating the hash, not proof of equal
timings. There is no comprehensive statistical side-channel test suite.

`Backoff.v` proves logarithmic guess bounds before a cap and linear bounds after
it, but is not connected to requests. Integration needs a policy for keying,
enumeration, account lockout, bounded counter storage and trustworthy time, plus
a new atomic-counter capability. Immutable account storage supplies no counters.

The gateway enforces Host/Origin policy, a 16 KiB streaming body limit and a
15-second read deadline; these decisions are unit-tested Rust, not proved Rocq.
The host bounds admission, fuel and memory. Those limits are not a wall-clock
deadline for crypto or a production resource policy. Replay protection,
revocation, TLS, key rotation and recovery tooling are not provided.

## Verification Commands

Run from the repository root with the project toolchain:

```sh
nix develop --command make test
nix develop --command make host-component
make test-host
cargo test --locked -p authentikate-argon2 -p authentikate-hmac
cargo test --locked -p authentikate-gateway
cargo fmt --all --check
```

The first command compiles the proofs and extraction and tests adapter ABI and
extracted control flow. Composed-host tests exercise actual Wasm providers:
signup/login/validation, independent HS256 interoperability, tampered tokens,
alternate algorithms, malformed inputs, HTTP policy and body limits, email
failure, cross-process atomic creation and persistence across fresh instances
and host restarts. Native crypto tests include RFC 4231 HMAC vectors.

The default `nix build` checks and installs the uncomposed service artifacts.
CI additionally builds providers, composes the HTTP artifact and runs the Rust
tests. Component/provider READMEs describe additional commands and test scope.

## Priorities

1. Persist the HMAC key atomically so authentication tokens remain valid across
   restarts, with restrictive access and an explicit rotation policy.
2. Move HTTP routing and Host/Origin policy into a separate proved layer while
   keeping transport and authentication concerns separate.
3. Define the leakage/threat model, Argon2 policy, cost migration and timing
   measurements before claiming stronger timing guarantees.
4. Connect rate limiting only after resolving keying, enumeration, lockout,
   clock and atomic-counter semantics.
5. Harden storage and deployment: filesystem guarantees, backup/recovery,
   resource budgets, TLS and observability without leaking secrets.
6. Simplify configuration, WIT staging and adapter composition; pursue host
   removal only while accounting for its capability and resource controls.
7. Add an HTTP/OpenAPI contract and reproducibly generated client.

Detailed implementation tasks and compiler constraints remain in
[TODO.md](TODO.md).
