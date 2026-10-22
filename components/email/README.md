# Stdout email provider

The component exports `authentikate:email/sender@0.1.0` (see [WIT](wit/email.wit)).

| Artifact | Backend | Required host capabilities |
| --- | --- | --- |
| `build/email-stdout.component.wasm` | Writes one JSON record per email to stdout | WASI 0.2 stdout and streams |

Build with `make email-stdout-component`, or `nix develop --command make email-stdout-component`.
The Nix development shell includes the Rust `wasm32-unknown-unknown` target. `make test-email-stdout` also runs
Rust unit tests and component tests with mocked WASI capabilities (no real email).
The development shell also supplies JCO for component tests; no npm installation
is needed. These Node tools are not used by the Rust web host.
CI runs the same complete stdout test suite.
The default Nix service build does not bundle this provider.
Run these commands from the repository root. The crate lives in
`components/email/` and shares the root workspace lockfile and target directory;
the internal service adapter is `components/service/adapters/email.wat`.

## Sending

Call `sender.send` with `from`, a `to` recipient list, `subject`, `text`, and an
optional `idempotency-key`. Only plain-text email is supported; `text` must be
nonempty and not just whitespace.
Messages are capped at 1 MiB of unencoded field content and 50 recipients.
Headers must be nonempty and contain no control characters. Address syntax and
sender domains are not verified.

The stdout backend prints the complete email, including recipients and body, as
one escaped JSON line. It does not deliver or deduplicate messages. Use it only
where logging email contents is acceptable, especially for password-reset links.

`send` returns success when stdout accepts the write, not when email is delivered.
This implementation reports invalid input and output-stream transport failures;
the shared sender contract retains its configuration and rejection error variants.
There are no automatic retries. A transport error can occur after partial output,
and retrying may duplicate output. The optional `idempotency-key` is validated and
logged, but does not enable deduplication.

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
defaults to `Authentikate <hello@example.test>`. Actual delivery requires a separate
implementation of the shared sender interface.
