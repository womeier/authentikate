# HTTP Gateway

The gateway exports `wasi:http/handler@0.3.0`. It uses p3 streams/futures for
HTTP bodies and p3 monotonic-clock waits for the 15-second read deadline.
The service and policy configuration imports remain synchronous; the service's
signing-key configuration is not available to the gateway.

Request bodies are counted up to 16 KiB plus one sentinel byte, including
chunked transfers. Oversize requests return 413, deadline expiry returns 408,
and interrupted transfers return 400. The trailer-result future must succeed
before the service is invoked. Response production runs in a spawned task so
it can make progress after the handler returns.

The host preserves HTTP/1 Host-header authority before p3 filters the header
from fields. The gateway checks that authority and Origin against its policy,
and rejects absolute-form targets using both the parsed scheme and path.

The vendored HTTP and clock signatures come from Wasmtime 50's p3 WIT,
`crates/wasi-http/src/p3/wit/deps/{http,clocks}.wit` (unused interfaces and most
documentation are omitted). Gateway bindings use wit-bindgen 0.57.1 with
`async-spawn`; other components retain their existing binding versions and p2
capabilities. Wasmtime 50 labels its p3 implementation experimental.

From the repository root:

```sh
make gateway-component
make test-host
cargo test --locked -p authentikate-gateway
```

Host integration tests cover chunked size boundaries, stalled and truncated
bodies, early rejection, absolute-form targets, and authentication/persistence.
