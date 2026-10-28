//! One interface, built with exactly one backend. Host capabilities use WASI 0.2.

#[cfg(any(
    all(feature = "stdout", feature = "smtp"),
    not(any(feature = "stdout", feature = "smtp"))
))]
compile_error!("select exactly one email backend: stdout or smtp");

#[cfg(feature = "smtp")]
mod smtp;

wit_bindgen::generate!({ world: "email-provider", path: "wit" });

use exports::authentikate::email::sender::{Error, Guest, Message};
use serde_json::{json, Value};

struct Component;

fn payload(email: &Message) -> Result<Value, Error> {
    let header = |s: &str| !s.trim().is_empty() && !s.chars().any(char::is_control);
    if !header(&email.from)
        || email.to.is_empty()
        || email.to.len() > 50
        || email.to.iter().any(|s| !header(s))
        || !header(&email.subject)
    {
        return Err(Error::InvalidMessage(
            "from, 1-50 recipients, and subject must be nonempty and contain no control characters"
                .into(),
        ));
    }
    if email.text.trim().is_empty() {
        return Err(Error::InvalidMessage("text is required".into()));
    }
    if email.idempotency_key.as_ref().is_some_and(|s| {
        s.is_empty() || s.len() > 255 || !s.bytes().all(|b| (33..=126).contains(&b))
    }) {
        return Err(Error::InvalidMessage(
            "idempotency-key must contain 1-255 visible ASCII characters".into(),
        ));
    }
    if email.from.len()
        + email.to.iter().map(String::len).sum::<usize>()
        + email.subject.len()
        + email.text.len()
        > 1024 * 1024
    {
        return Err(Error::InvalidMessage("message exceeds 1 MiB".into()));
    }
    Ok(json!({
        "from": email.from,
        "to": email.to,
        "subject": email.subject,
        "text": email.text,
    }))
}

// WASI blocking-write-and-flush accepts at most 4096 bytes per call.
#[cfg(feature = "stdout")]
fn write(stream: &wasi::io::streams::OutputStream, bytes: &[u8]) -> Result<(), Error> {
    for chunk in bytes.chunks(4096) {
        stream
            .blocking_write_and_flush(chunk)
            .map_err(|_| Error::Transport("output stream failed".into()))?;
    }
    Ok(())
}

impl Guest for Component {
    fn send(email: Message) -> Result<(), Error> {
        #[cfg(feature = "stdout")]
        {
            let payload = payload(&email)?;
            let mut record = json!({"backend": "stdout", "email": payload});
            if let Some(key) = email.idempotency_key {
                record["idempotency_key"] = json!(key);
            }
            let line = format!("{record}\n");
            write(&wasi::cli::stdout::get_stdout(), line.as_bytes())
        }
        #[cfg(feature = "smtp")]
        {
            smtp::send(&email)
        }
    }
}

export!(Component);

#[cfg(test)]
mod tests {
    use super::*;

    fn message() -> Message {
        Message {
            from: "Authentikate <hello@example.com>".into(),
            to: vec!["user@example.com".into()],
            subject: "Welcome \"friend\"".into(),
            text: "Hello\nworld".into(),
            idempotency_key: Some("welcome-123".into()),
        }
    }

    #[test]
    fn serializes_payload() {
        let email = message();
        let value = payload(&email).unwrap();
        let value: Value = serde_json::from_str(&value.to_string()).unwrap();
        assert_eq!(value["to"], json!(["user@example.com"]));
        assert_eq!(value["subject"], email.subject);
        assert_eq!(value["text"], email.text);
        assert!(value.get("idempotency_key").is_none());
    }

    #[test]
    fn rejects_invalid_messages() {
        let mut email = message();
        email.to.clear();
        assert!(matches!(payload(&email), Err(Error::InvalidMessage(_))));
        email = message();
        email.from.push_str("\r\nBcc: attacker@example.com");
        assert!(payload(&email).is_err());
        email = message();
        email.subject.clear();
        assert!(payload(&email).is_err());
        email = message();
        email.text.clear();
        assert!(payload(&email).is_err());
        email.text = " \n\t".into();
        assert!(payload(&email).is_err());
        email = message();
        email.idempotency_key = Some("invalid\nkey".into());
        assert!(payload(&email).is_err());
        email = message();
        email.text = "x".repeat(1024 * 1024);
        assert!(payload(&email).is_err());
    }
}
