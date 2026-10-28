Written by LLMs. TODO: check.

# Email providers

The component exports `authentikate:email/sender@0.1.0` (see [WIT](wit/email.wit)).

| Artifact | Backend | Required host capabilities |
| --- | --- | --- |
| `build/email-stdout.component.wasm` | Writes one JSON record per email to stdout | WASI 0.2 stdout and streams |
| `build/email-smtp.component.wasm` | Sends plain-text email directly to `127.0.0.1:25` | WASI 0.2.4 sockets (instance-network, network types, TCP, TCP create-socket), streams, polling, and monotonic clock |

The default Cargo feature is `stdout`. Select exactly one backend; build SMTP
with `--no-default-features --features smtp`. Selecting both or neither is
a compile-time error. Both artifacts export the same WIT interface, and the WASI
dependencies remain pinned to 0.2.4 through `wasi = "=0.14.2"`.

Build with `make email-stdout-component` or `make email-smtp-component`, optionally
prefixed with `nix develop --command`.
The Nix development shell includes the Rust `wasm32-unknown-unknown` target. `make test-email-stdout` also runs
Rust unit tests and component tests with mocked WASI capabilities (no real email).
The development shell also supplies JCO for component tests; no npm installation
is needed. Node is used for component tests, not for live email delivery.
CI runs both backend test suites with mocked capabilities, never live sends.
The default Nix service build does not bundle this provider.
Run these commands from the repository root. The crate lives in
`components/email/` and shares the root workspace lockfile and target directory;
the internal service adapter is `components/service/adapters/email.wat`.

## Sending

Call `sender.send` with `from`, a `to` recipient list, `subject`, `text`, and an
optional `idempotency-key`. Only plain-text email is supported; `text` must be
nonempty and not just whitespace.
Messages are capped at 1 MiB of unencoded field content and 50 recipients.
Headers must be nonempty and contain no control characters. The stdout backend
does not verify address syntax or sender domains. The SMTP backend enforces
strict bare ASCII recipient mailboxes (no display names or internationalized
mailboxes). The sender must be a bare ASCII mailbox or `Display Name <mailbox>`;
the simple display name permits only ASCII letters, digits, spaces, dots,
underscores, and hyphens, with no leading or trailing whitespace. Sender domains
are not verified.

The stdout backend prints the complete email, including recipients and body, as
one escaped JSON line. It does not deliver or deduplicate messages. Use it only
where logging email contents is acceptable, especially for password-reset links.

`send` returns success when stdout accepts the write, not when email is delivered.
This backend reports invalid input and output-stream transport failures.
There are no automatic retries. A transport error can occur after partial output,
and retrying may duplicate output. The optional `idempotency-key` is validated and
logged, but does not enable deduplication.

## Local SMTP

The backend connects directly to the fixed endpoint `127.0.0.1:25` through WASI
TCP. Install and configure a local SMTP MTA to accept submission without
authentication or TLS and queue messages for onward delivery. Restrict its
submission listener to loopback and its relay permissions accordingly; do not
expose an open relay. Nix does not install or configure the MTA. No `mail`
command, Node helper, tokens, Lettermint account, or outgoing HTTP is required.

After the server's `220` greeting, the component sends `EHLO`, `MAIL FROM`, one
`RCPT TO` per recipient, and `DATA`. It waits for the final `250` reply after the
message terminator before reporting success. This means server acceptance, not
confirmed delivery. SMTP `4xx` and `5xx` replies become `rejected(status)`;
transport failures and malformed or unexpected replies produce sanitized
transport errors. A best-effort `QUIT` after acceptance does not change success.

Messages use plain-text UTF-8 MIME with a base64-encoded body and encoded-word
subject headers. Body line endings are normalized to CRLF before encoding, and
base64 lines are wrapped at 76 characters. No SMTPUTF8, authentication, or
STARTTLS support is required or attempted. The backend does not log email contents.

Connection and protocol I/O share a 30-second monotonic deadline, using
nonblocking WASI streams and polling rather than separate HTTP phase timeouts.
There are no automatic retries or deduplication. The optional `idempotency-key`
is validated but otherwise unused by SMTP: it is neither transmitted nor stored.
A transport failure can leave acceptance uncertain, and retrying may send
duplicates.

`nix run .#authentikate-live` selects SMTP and requires existing configuration,
`signing.key`, and any overridden accounts directory, plus a configured `service.email_from`
accepted by the MTA. It does not generate a signing key or start an MTA. Wasmtime
enables TCP and inherited host network access, with IP name lookup, UDP, and
environment inheritance disabled
(`-S tcp=y,inherit-network=y,allow-ip-name-lookup=n,udp=n,inherit-env=n`).
The component fixes the destination to `127.0.0.1:25`, but stock Wasmtime does not
offer a destination-specific TCP allowlist; independent enforcement needs OS
firewall rules. No outgoing WASI HTTP capability is needed. The live launcher's overall execution
timeout remains 90 seconds.

## Backend Tests

Run from the repository root:

```sh
nix develop --command make test-email-stdout test-email-smtp
```

The component tests transpile the actual built Wasm artifacts with JCO and supply
only mock WASI imports, without live email delivery or a local MTA. The SMTP suite
uses mocked socket, stream, polling, and monotonic-clock capabilities. The stdout
suite remains independent and unchanged.

`make test-smtp-runtime` runs the real live composition against a fake SMTP server
on `127.0.0.1:25`, checking acceptance, rejection, and account persistence. It
delivers no real email and requires permission to bind port 25 with no existing
listener on that port.

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
JavaScript replacement. Set `service.email_from` in `/config/config.json`; the
root example uses `Authentikate <hello@example.test>`. There is no sender
environment-variable setting. Use Wasmtime's `--no-logging-prefix` for plain JSON
stdout records. `nix run .#authentikate-live` explicitly selects the SMTP
composition and connects to the local MTA; see the root README for provisioning
and capability limits. `authentikate-local` and the default composition still use
stdout, and building the SMTP artifact alone does not enable delivery.
