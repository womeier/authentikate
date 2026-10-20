//! One interface, built with exactly one backend. Host capabilities use WASI 0.2.

#[cfg(any(
    all(feature = "stdout", feature = "lettermint"),
    not(any(feature = "stdout", feature = "lettermint"))
))]
compile_error!("select exactly one email backend: stdout or lettermint");

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
    if email.text.trim().is_empty() && email.html.as_ref().is_none_or(|s| s.trim().is_empty()) {
        return Err(Error::InvalidMessage("text or html is required".into()));
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
        + email.html.as_ref().map_or(0, String::len)
        > 1024 * 1024
    {
        return Err(Error::InvalidMessage("message exceeds 1 MiB".into()));
    }
    let mut value = json!({
        "from": email.from,
        "to": email.to,
        "subject": email.subject,
        "text": email.text,
    });
    if let Some(html) = &email.html {
        value["html"] = json!(html);
    }
    Ok(value)
}

// WASI blocking-write-and-flush accepts at most 4096 bytes per call.
fn write(stream: &wasi::io::streams::OutputStream, bytes: &[u8]) -> Result<(), Error> {
    for chunk in bytes.chunks(4096) {
        stream
            .blocking_write_and_flush(chunk)
            .map_err(|_| Error::Transport("output stream failed".into()))?;
    }
    Ok(())
}

#[cfg(feature = "lettermint")]
fn token(value: Option<String>) -> Result<String, Error> {
    value
        .filter(|s| !s.is_empty() && s.bytes().all(|b| (33..=126).contains(&b)))
        .ok_or_else(|| {
            Error::Configuration("LETTERMINT_PROJECT_TOKEN is missing or invalid".into())
        })
}

#[cfg(feature = "lettermint")]
fn accepted(status: u16) -> Result<(), Error> {
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(Error::Rejected(status))
    }
}

impl Guest for Component {
    fn send(email: Message) -> Result<(), Error> {
        let payload = payload(&email)?;
        #[cfg(feature = "stdout")]
        {
            let mut record = json!({"backend": "stdout", "email": payload});
            if let Some(key) = email.idempotency_key {
                record["idempotency_key"] = json!(key);
            }
            let line = format!("{record}\n");
            write(&wasi::cli::stdout::get_stdout(), line.as_bytes())
        }
        #[cfg(feature = "lettermint")]
        {
            use wasi::http::{outgoing_handler, types::*};

            let credential = token(
                wasi::cli::environment::get_environment()
                    .into_iter()
                    .find(|(name, _)| name == "LETTERMINT_PROJECT_TOKEN")
                    .map(|(_, value)| value),
            )?;
            let mut headers = vec![
                ("content-type".into(), b"application/json".to_vec()),
                ("accept".into(), b"application/json".to_vec()),
                ("x-lettermint-token".into(), credential.into_bytes()),
            ];
            if let Some(key) = email.idempotency_key {
                headers.push(("idempotency-key".into(), key.into_bytes()));
            }
            let headers = Fields::from_list(&headers)
                .map_err(|_| Error::Configuration("invalid request headers".into()))?;
            let request = OutgoingRequest::new(headers);
            request.set_method(&Method::Post).unwrap();
            request.set_scheme(Some(&Scheme::Https)).unwrap();
            request.set_authority(Some("api.lettermint.co")).unwrap();
            request.set_path_with_query(Some("/v1/send")).unwrap();
            let body = request.body().unwrap();
            let options = RequestOptions::new();
            options
                .set_connect_timeout(Some(30_000_000_000))
                .map_err(|_| Error::Configuration("connect timeout unsupported".into()))?;
            options
                .set_first_byte_timeout(Some(30_000_000_000))
                .map_err(|_| Error::Configuration("first-byte timeout unsupported".into()))?;
            options
                .set_between_bytes_timeout(Some(30_000_000_000))
                .map_err(|_| Error::Configuration("between-byte timeout unsupported".into()))?;
            // Dispatch before writing: a large body may need the host to drain it.
            let response = outgoing_handler::handle(request, Some(options))
                .map_err(|_| Error::Transport("HTTP request failed".into()))?;
            let stream = body.write().unwrap();
            write(&stream, payload.to_string().as_bytes())?;
            drop(stream);
            OutgoingBody::finish(body, None)
                .map_err(|_| Error::Transport("HTTP request body failed".into()))?;
            let pollable = response.subscribe();
            let response = loop {
                if let Some(result) = response.get() {
                    break result
                        .map_err(|_| Error::Transport("HTTP response already consumed".into()))?
                        .map_err(|_| Error::Transport("HTTP request failed".into()))?;
                }
                pollable.block();
            };
            // Do not return provider bodies: they may echo credentials or personal data.
            accepted(response.status())
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
            html: None,
            idempotency_key: Some("welcome-123".into()),
        }
    }

    #[test]
    fn serializes_api_payload() {
        let mut email = message();
        let value = payload(&email).unwrap();
        let value: Value = serde_json::from_str(&value.to_string()).unwrap();
        assert_eq!(value["to"], json!(["user@example.com"]));
        assert_eq!(value["subject"], email.subject);
        assert_eq!(value["text"], email.text);
        assert!(value.get("html").is_none());
        assert!(value.get("idempotency_key").is_none());
        email.html = Some("<p>Hello</p>".into());
        assert_eq!(payload(&email).unwrap()["html"], "<p>Hello</p>");
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
        email.html = Some("<p>Hello</p>".into());
        assert!(payload(&email).is_ok());
        email.idempotency_key = Some("invalid\nkey".into());
        assert!(payload(&email).is_err());
        email = message();
        email.text = "x".repeat(1024 * 1024);
        assert!(payload(&email).is_err());
    }

    #[cfg(feature = "lettermint")]
    #[test]
    fn credentials_and_provider_status() {
        assert!(token(None).is_err());
        assert!(token(Some("\r\nsecret".into())).is_err());
        assert_eq!(token(Some("secret".into())).unwrap(), "secret");
        assert!(accepted(202).is_ok());
        for status in [302, 401, 403, 422, 429, 500] {
            assert!(matches!(accepted(status), Err(Error::Rejected(s)) if s == status));
        }
    }
}
