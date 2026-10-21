# Email providers

Both artifacts export `authentikate:email/sender@0.1.0` (see [WIT](wit/email.wit)).
The Rust crate is built twice with mutually exclusive backend features:

| Artifact | Backend | Required host capabilities |
| --- | --- | --- |
| `build/email-stdout.component.wasm` | Writes one JSON record per email to stdout | WASI 0.2 stdout and streams |
| `build/email-lettermint.component.wasm` | POSTs JSON to `https://api.lettermint.co/v1/send` | WASI 0.2 environment, HTTP, I/O, clocks |

Build with `make email-components`, or `nix develop --command make email-components`.
The Nix development shell includes the Rust `wasm32-unknown-unknown` target. `make test-email` also runs
Rust unit tests and component tests with mocked WASI capabilities (no real email).
The development shell also supplies JCO for component tests; no npm installation
is needed. These Node tools are not used by the Rust web host.
CI runs `make test-email-stdout`, which builds and tests only the stdout backend;
it does not build the Lettermint backend or require its credentials.
The default Nix service build does not bundle these providers.
Run these commands from the repository root. The crate and its lockfile live in
`providers/email/`; the internal service adapter is `component/adapters/email.wat`.

## Sending

Call `sender.send` with `from`, a `to` recipient list, `subject`, `text`, and an
optional `idempotency-key`. Only plain-text email is supported; `text` must be
nonempty and not just whitespace.
Messages are capped at 1 MiB of unencoded field content and 50 recipients.
Address syntax and sender-domain verification are ultimately checked by Lettermint.

The stdout backend prints the complete email, including recipients and body, as
one escaped JSON line. It does not deliver or deduplicate messages. Use it only
where logging email contents is acceptable, especially for password-reset links.

For Lettermint, provide `LETTERMINT_PROJECT_TOKEN` through the component's WASI
environment, using a project sending token and a verified sender domain. The
token is sent in `x-lettermint-token`, never in the email payload or logs. Grant
outbound HTTPS access only to `api.lettermint.co:443`. The endpoint is fixed;
redirect responses are rejected rather than followed with credentials.

`send` returns success when the provider accepts the request, not when delivery
finishes. Errors distinguish invalid input, missing/invalid configuration,
transport failures, and provider rejection (HTTP status only). Provider response
bodies are not logged or returned. Requests set 30-second connect, first-byte,
and between-byte timeouts; the runtime should also impose an overall deadline.

There are no automatic retries. A transport error can occur after acceptance;
reuse the same `idempotency-key` and message when retrying to avoid duplicate
sends. The host/orchestrator is responsible for durable retries and delivery
tracking. No production credentials are required for the test suite.

## Signup integration

The Rocq authentication service imports this interface. After an acknowledged
account write, signup sends a plain-text welcome message to the account email,
using the API configuration's `email-from` bytes as the sender. Only sender,
recipient, subject, and welcome text cross the email boundary, never passwords
or password hashes. The adapter rejects invalid UTF-8 before calling the provider.

`201` requires both persistence and email acceptance. An email error returns
`500` without rolling back the stored account; a retry returns `409` and does not
send again. This synchronous flow has no durable email retries or verification
tokens, and does not make account creation atomic.

The web demo and CI HTTP tests bind the real stdout Wasm component, not a
JavaScript replacement. `SIGNUP_EMAIL_FROM` configures the demo's sender and
defaults to `Authentikate <hello@example.test>`. Production hosts should bind
the Lettermint component and configure a sender on their verified domain.
