# Configuration Provider

Exports the unchanged `authentikate:config/service@0.1.0` and
`authentikate:config/policy@0.1.0` interfaces. The build script stages the
authoritative `../../wit/config.wit`; no vendored WIT dependencies are needed.
`wit-bindgen` 0.46 generates the exports and `wasi` =0.14.2 supplies pinned
WASI 0.2.4 filesystem imports.

## Provisioning

The provider reads a directory preopen named exactly `/config`:

- `config.json`: at most 65,536 bytes, including whitespace, UTF-8 JSON.
- `signing.key`: unpadded base64url (RFC 4648 Section 5) decoding to exactly 32 bytes, provisioned
  with a cryptographically secure random generator and persisted across requests,
  instances and restarts. An optional trailing LF or CRLF is accepted; other
  whitespace, raw binary, hex, standard base64, and padded encodings are rejected. The file is
  bounded to 45 bytes. Generate a new key with
  `openssl rand -base64 32 | tr '+/' '-_' | tr -d '='`, never a
  password.

The root [config.example.json](../../config.example.json) contains this example:

```json
{
  "service": {
    "issuer": "authentikate",
    "token_ttl_seconds": 600,
    "email_from": "Authentikate <hello@example.test>"
  },
  "policy": {
    "approved_origin": null,
    "approved_authorities": ["localhost:3000", "127.0.0.1:3000", "[::1]:3000"]
  }
}
```

All fields are required except `approved_origin`, which may be absent or null.
Unknown and duplicate fields are rejected at every record level. TTL is a positive
`u64`. Issuer is nonblank printable ASCII without quote or backslash, because the
Rocq JSON printer does not escape these. Sender accepts a conservative ASCII
dot-atom mailbox, optionally preceded by `Display Name <...>`, not arbitrary RFC
5322 address syntax or control characters.

Policy requires an approved HTTP(S) origin or a nonempty authority list. Origins
contain no credentials, query, fragment, or path other than an optional `/`.
Normalization uses `url::Url`, including lowercase
hosts, IDNA, IPv6 and removal of default ports. Authorities are normalized as HTTP
authorities for the gateway's HTTP fallback mode, sorted and deduplicated. All
entries are validated even when an approved origin takes precedence. DNS wildcards,
invalid labels, whitespace, backslashes, empty ports and port zero are rejected.
For runtime-selected listening ports, the operator must provision the actual
bound authorities before serving requests; this component cannot discover them.
Non-loopback deployment requires manually provisioning an explicit approved origin
and the listener/proxy; the CLI has no custom host safety validation.

Each `get` rereads and validates JSON. Service `get` additionally reads the key;
policy `get` never opens it and cannot return it. Missing files/preopen, symlinks,
nonregular files, read failures, malformed configuration, invalid base64url and incorrect decoded key length
trap with a constant message, rather than returning defaults. There is no key
generation or write operation. Temporary read/key buffers are zeroized; the
service export necessarily transfers key bytes to the service consumer.

Configuration is reread on every request. Stop all serving processes before
multi-file updates: separate files and separate exports are not an atomic snapshot.
See the [root provisioning commands](../../README.md#run-the-demo) for restrictive
directory permissions and one-time random key creation using shell noclobber.
Never truncate or regenerate an existing key during startup; a missing or malformed
key fails closed. A retained key preserves token validity across restarts.

In the final composition, config and storage share all WASI filesystem preopens.
The CLI grants both `/config` and `/accounts` writable access, not a read-only
config sandbox or per-provider isolation. This implementation only reads, but
both providers must be trusted with those capabilities. The gateway imports no
filesystem interfaces and receives only policy, never the service/key export.
Runtime errors should not be echoed to HTTP clients.

## Build And Integration

This crate shares the root Cargo workspace, lockfile and target directory.
From the repository root, in the project development shell:

```sh
cargo test --locked -p authentikate-config
make config-component
make app-component
make test-app
```

Build prerequisites: Rust with the `wasm32-unknown-unknown` target and
`wasm-tools`. No WASI Preview 1 adapter is required. The resulting component's
WASI `filesystem/types@0.2.4` and `filesystem/preopens@0.2.4` imports must be
supplied by the WASI Preview 2 runtime.

`make config-component` builds `build/config.component.wasm` from
`target/wasm32-unknown-unknown/release/authentikate_config.wasm` and validates it.
Root [composition.wac](../../composition.wac) instantiates this provider once,
wiring `service` to the service adapter and `policy` to the gateway. Neither
configuration export is re-exported publicly. `make compose-app` rebuilds config,
storage and gateway and composes existing service/crypto/email artifacts into
`build/app.component.wasm`; `make app-component` builds all prerequisites.

Native tests exercise only the pure parser, base64url decoding and decoded-key-length validator. They do not
invoke WASI or test runtime preopen permissions, trapping, or composition wiring.
`make test-app` exercises the composed provider through the real Wasmtime CLI,
including missing/malformed provisioning and persistent-key restart behavior.
