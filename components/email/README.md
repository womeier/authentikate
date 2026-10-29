(written by LLM, revised)

# Email providers

The component exports `authentikate:email/sender@0.1.0` (see [WIT](wit/email.wit)).

| Artifact | Backend | Required host capabilities |
| --- | --- | --- |
| `build/email-stdout.component.wasm` | Writes one JSON record per email to stdout | WASI 0.2 stdout and streams |
| `build/email-smtp.component.wasm` | Sends plain-text email directly to `127.0.0.1:25` | WASI 0.2.4 sockets (instance-network, network types, TCP, TCP create-socket), streams, polling, and monotonic clock |

### Build
Build with `make email-stdout-component` or `make email-smtp-component`.

The make target uses exactly one of the two backends:
- the default Cargo feature is `stdout`.
- build SMTP with `--no-default-features --features smtp`.

### Testing
Run from the repository root:

```sh
nix develop --command make test-email-stdout test-email-smtp
```

`make test-email-stdout` runs Rust unit tests and component tests with mocked WASI capabilities (no real email).
The development shell also supplies JCO for component tests. Node is used for component tests, not for live email delivery.
CI runs both backend test suites with mocked capabilities, never live sends.
The default Nix service build does not bundle this provider.
Run these commands from the repository root. The crate lives in
`components/email/` and shares the root workspace lockfile and target directory;
the internal service adapter is `components/service/adapters/email.wat`.

`make test-smtp-runtime` runs the real live composition against a fake SMTP server
on `127.0.0.1:25`, checking acceptance, rejection, and account persistence. It
delivers no real email and requires permission to bind port 25 with no existing
listener on that port.


### Email Sending
Only plain-text email is supported, no `html`; `text` must be nonempty and not just whitespace.
Messages are capped at 1 MiB of unencoded field content and 50 recipients.
Headers must be nonempty and contain no control characters. The stdout backend
does not verify address syntax or sender domains. The SMTP backend enforces
strict bare ASCII recipient mailboxes (no display names or internationalized
mailboxes). The sender must be a bare ASCII mailbox or `Display Name <mailbox>`;
the simple display name permits only ASCII letters, digits, spaces, dots,
underscores, and hyphens, with no leading or trailing whitespace. Sender domains
are not verified.

#### Stdout
The stdout backend prints the complete email, including recipients and body, as
one escaped JSON line. It does not deliver or deduplicate messages. Use it only
where logging email contents is acceptable, especially for password-reset links.

`send` returns success when stdout accepts the write, not when email is delivered.
This backend reports invalid input and output-stream transport failures.
There are no automatic retries. A transport error can occur after partial output,
and retrying may duplicate output. The optional `idempotency-key` is validated and
logged, but does not enable deduplication.

#### Local SMTP
The backend connects directly to the SMTP server at `127.0.0.1:25` through WASI TCP.
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
