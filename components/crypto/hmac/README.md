Written by LLMs. TODO: check.

# HS256 Crypto Component

`authentikate:crypto/hmac@0.1.0` imports no host capabilities and exposes only
`import-key`, `sign` and `verify`. It uses pinned `libcrux-hmac` 0.0.9's
`hmac_sha2_256`, with a full 32-byte tag and `subtle` constant-time comparison.
Wrong-sized tags and unknown handles are errors; an unequal full-size tag is
`false`. There is no algorithm negotiation or tag truncation.

The host provisions exactly 32 random key bytes, meeting HS256's minimum key
length. Both generation and verification take the same opaque integer handle.
An instance has a bounded append-only table of 1024 keys; handles are never
reused. Imported and stored key buffers are zeroized on drop. Neither key bytes
nor a public key are exposed through this component's exports. The service's
adapter imports the configured key for each fresh request instance; the Rocq
heap and HTTP gateway receive no secret bytes. The host and canonical ABI
marshalling still handle copies. There is no complete secret-erasure guarantee.

HMAC is symmetric: anyone given the verification secret can mint tokens too.
The host currently keeps the key only in memory, so restarting it invalidates
existing JWTs. Persisting the key is deferred in `TODO.md`; account persistence
is independent. This replaces Ed25519/EdDSA rather than adding another accepted
algorithm. Old EdDSA tokens are rejected.

## Verification Scope

Libcrux documents this crate as safe Rust translated from verified C originating
in HACL*. The F* proofs establish primitive memory safety, functional correctness
and source-level secret independence. Those guarantees do not automatically
extend to the wrapper, `subtle`, key provisioning, adapters, Rust-to-Wasm
compilation, Wasmtime, or executable side-channel resistance. Libcrux's internal
key-derived temporary buffers are not guaranteed wiped by this wrapper.

`cargo test --locked -p authentikate-hmac` checks RFC 4231 SHA-256 vectors,
generation/verification, tampered messages/tags, wrong keys and lengths, and
handle bounds. The composed-host suite independently verifies generated JWTs
with RustCrypto HMAC (a test-only dependency), accepts externally generated
HS256 tokens and rejects alternate algorithms and truncated/oversized tags.
