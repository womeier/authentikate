use super::{Error, Message};
use std::collections::VecDeque;
use wasi::{
    clocks::monotonic_clock,
    io::{
        poll::{poll, Pollable},
        streams::{InputStream, OutputStream},
    },
    sockets::{
        instance_network::instance_network,
        network::{ErrorCode, IpAddressFamily, IpSocketAddress, Ipv4SocketAddress},
        tcp_create_socket::create_tcp_socket,
    },
};

fn transport() -> Error {
    Error::Transport("SMTP transport or protocol failure".into())
}

fn invalid() -> Error {
    Error::InvalidMessage(
        "SMTP requires strict ASCII mailboxes and a simple ASCII sender display name".into(),
    )
}

fn mailbox(value: &str) -> Result<&str, Error> {
    let (local, domain) = value.split_once('@').ok_or_else(invalid)?;
    if value.len() > 254
        || local.is_empty()
        || local.len() > 64
        || local.split('.').any(str::is_empty)
        || !local
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".!#$%&'*+-/=?^_`{|}~".contains(&b))
        || domain.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || !label.as_bytes()[0].is_ascii_alphanumeric()
                || !label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err(invalid());
    }
    Ok(value)
}

fn sender(value: &str) -> Result<(&str, Option<&str>), Error> {
    if let Some((display, address)) = value.split_once(" <") {
        if display.is_empty()
            || display.trim() != display
            || !display
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b" ._-".contains(&b))
        {
            return Err(invalid());
        }
        Ok((
            mailbox(address.strip_suffix('>').ok_or_else(invalid)?)?,
            Some(display),
        ))
    } else {
        Ok((mailbox(value)?, None))
    }
}

fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let a = chunk[0];
        let b = chunk.get(1).copied().unwrap_or(0);
        let c = chunk.get(2).copied().unwrap_or(0);
        out.push(TABLE[(a >> 2) as usize] as char);
        out.push(TABLE[(((a & 3) << 4) | (b >> 4)) as usize] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(((b & 15) << 2) | (c >> 6)) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[(c & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

// Each encoded word is at most 72 bytes, and never splits a UTF-8 character.
fn encoded_words(mut value: &str, out: &mut String) {
    while !value.is_empty() {
        let mut end = value.len().min(45);
        while !value.is_char_boundary(end) {
            end -= 1;
        }
        out.push_str("\r\n =?UTF-8?B?");
        out.push_str(&base64(&value.as_bytes()[..end]));
        out.push_str("?=");
        value = &value[end..];
    }
}

fn normalize(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len());
    let mut bytes = text.bytes().peekable();
    while let Some(byte) = bytes.next() {
        if byte == b'\r' || byte == b'\n' {
            if byte == b'\r' && bytes.peek() == Some(&b'\n') {
                bytes.next();
            }
            out.extend_from_slice(b"\r\n");
        } else {
            out.push(byte);
        }
    }
    out
}

struct Prepared<'a> {
    from: &'a str,
    to: Vec<&'a str>,
    data: String,
}

fn prepare(email: &Message) -> Result<Prepared<'_>, Error> {
    // Also validate here so this boundary cannot be used without the shared cap.
    super::payload(email)?;
    let (from, display) = sender(&email.from)?;
    let to = email
        .to
        .iter()
        .map(|s| mailbox(s))
        .collect::<Result<Vec<_>, _>>()?;
    let mut data = String::from("From:");
    if let Some(display) = display {
        encoded_words(display, &mut data);
        data.push_str("\r\n");
    }
    data.push_str(&format!(" <{from}>\r\nTo:"));
    for (index, address) in to.iter().enumerate() {
        if index != 0 {
            data.push(',');
        }
        data.push_str(&format!("\r\n <{address}>"));
    }
    data.push_str("\r\nSubject:");
    encoded_words(&email.subject, &mut data);
    data.push_str("\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n");
    let body = base64(&normalize(&email.text));
    for line in body.as_bytes().chunks(76) {
        // base64 is ASCII; slicing it cannot split a codepoint.
        data.push_str(std::str::from_utf8(line).unwrap());
        data.push_str("\r\n");
    }
    data.push_str(".\r\n");
    Ok(Prepared { from, to, data })
}

#[derive(Default)]
struct Reply {
    line: Vec<u8>,
    code: Option<u16>,
    lines: usize,
    bytes: usize,
}

impl Reply {
    fn push(&mut self, byte: u8) -> Result<Option<u16>, Error> {
        self.bytes += 1;
        self.line.push(byte);
        // RFC 5321 line limit includes CRLF; cap the entire multiline reply too.
        if self.line.len() > 512 || self.bytes > 16 * 1024 {
            return Err(transport());
        }
        if byte != b'\n' {
            return Ok(None);
        }
        self.lines += 1;
        let line = &self.line;
        if self.lines > 64
            || line.len() < 5
            || !line.ends_with(b"\r\n")
            || !(b'2'..=b'5').contains(&line[0])
            || !line[1..3].iter().all(u8::is_ascii_digit)
            || !(matches!(line[3], b' ' | b'-') || line.len() == 5)
            || (line.len() > 5
                && !line[4..line.len() - 2]
                    .iter()
                    .all(|b| *b == b'\t' || (32..=126).contains(b)))
        {
            return Err(transport());
        }
        let code = u16::from(line[0] - b'0') * 100
            + u16::from(line[1] - b'0') * 10
            + u16::from(line[2] - b'0');
        if self.code.is_some_and(|previous| previous != code) {
            return Err(transport());
        }
        self.code = Some(code);
        // RFC 5321 also requires clients to accept a code without reply text.
        let complete = line[3] != b'-';
        self.line.clear();
        Ok(complete.then_some(code))
    }
}

fn expected(code: u16, allowed: &[u16]) -> Result<(), Error> {
    if allowed.contains(&code) {
        Ok(())
    } else if (400..600).contains(&code) {
        Err(Error::Rejected(code))
    } else {
        Err(transport())
    }
}

struct Deadline {
    end: u64,
    timer: Pollable,
}

impl Deadline {
    fn new() -> Self {
        let end = monotonic_clock::now().saturating_add(30_000_000_000);
        Self {
            end,
            timer: monotonic_clock::subscribe_instant(end),
        }
    }

    fn check(&self) -> Result<(), Error> {
        if monotonic_clock::now() >= self.end {
            Err(Error::Transport("SMTP deadline exceeded".into()))
        } else {
            Ok(())
        }
    }

    fn wait(&self, ready: &Pollable) -> Result<(), Error> {
        self.check()?;
        poll(&[ready, &self.timer]);
        self.check()
    }
}

struct Connection<'a> {
    input: InputStream,
    output: OutputStream,
    pending: VecDeque<u8>,
    deadline: &'a Deadline,
}

impl Connection<'_> {
    fn reply(&mut self, allowed: &[u16]) -> Result<(), Error> {
        let mut reply = Reply::default();
        loop {
            self.deadline.check()?;
            if let Some(byte) = self.pending.pop_front() {
                if let Some(code) = reply.push(byte)? {
                    return expected(code, allowed);
                }
            } else {
                let bytes = self.input.read(512).map_err(|_| transport())?;
                if bytes.is_empty() {
                    self.deadline.wait(&self.input.subscribe())?;
                } else {
                    self.pending.extend(bytes);
                }
            }
        }
    }

    fn write(&self, mut bytes: &[u8]) -> Result<(), Error> {
        while !bytes.is_empty() {
            self.deadline.check()?;
            let permit = self.output.check_write().map_err(|_| transport())?;
            if permit == 0 {
                self.deadline.wait(&self.output.subscribe())?;
                continue;
            }
            let len = permit.min(bytes.len() as u64).min(4096) as usize;
            self.output.write(&bytes[..len]).map_err(|_| transport())?;
            bytes = &bytes[len..];
        }
        self.deadline.check()?;
        self.output.flush().map_err(|_| transport())?;
        loop {
            self.deadline.check()?;
            if self.output.check_write().map_err(|_| transport())? > 0 {
                return Ok(());
            }
            self.deadline.wait(&self.output.subscribe())?;
        }
    }

    fn command(&mut self, command: &str, allowed: &[u16]) -> Result<(), Error> {
        self.write(command.as_bytes())?;
        self.reply(allowed)
    }
}

pub(super) fn send(email: &Message) -> Result<(), Error> {
    let prepared = prepare(email)?;
    let deadline = Deadline::new();
    let network = instance_network();
    let socket = create_tcp_socket(IpAddressFamily::Ipv4).map_err(|_| transport())?;
    deadline.check()?;
    socket
        .start_connect(
            &network,
            IpSocketAddress::Ipv4(Ipv4SocketAddress {
                port: 25,
                address: (127, 0, 0, 1),
            }),
        )
        .map_err(|_| transport())?;
    let (input, output) = loop {
        deadline.check()?;
        match socket.finish_connect() {
            Ok(streams) => break streams,
            Err(ErrorCode::WouldBlock) => deadline.wait(&socket.subscribe())?,
            Err(_) => return Err(transport()),
        }
    };
    // Streams and their temporary pollables must be dropped before the socket.
    let mut connection = Connection {
        input,
        output,
        pending: VecDeque::new(),
        deadline: &deadline,
    };
    connection.reply(&[220])?;
    connection.command("EHLO authentikate.local\r\n", &[250])?;
    connection.command(&format!("MAIL FROM:<{}>\r\n", prepared.from), &[250])?;
    for address in prepared.to {
        connection.command(&format!("RCPT TO:<{address}>\r\n"), &[250, 251])?;
    }
    connection.command("DATA\r\n", &[354])?;
    connection.write(prepared.data.as_bytes())?;
    connection.reply(&[250])?;
    // Acceptance is final. QUIT is optional and must never wait or change success.
    if deadline.check().is_ok()
        && connection.output.check_write().is_ok_and(|n| n >= 6)
        && connection.output.write(b"QUIT\r\n").is_ok()
    {
        let _ = connection.output.flush();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message() -> Message {
        Message {
            from: "Authentikate <hello@example.test>".into(),
            to: vec!["first@example.test".into(), "second@example.test".into()],
            subject: "Welcome to Authentikate".into(),
            text: "Hello\nworld".into(),
            idempotency_key: Some("welcome-123".into()),
        }
    }

    fn parse(bytes: &[u8]) -> Result<u16, Error> {
        let mut reply = Reply::default();
        for (index, byte) in bytes.iter().enumerate() {
            if let Some(code) = reply.push(*byte)? {
                assert_eq!(index + 1, bytes.len());
                return Ok(code);
            }
        }
        Err(transport())
    }

    fn decode(encoded: &str) -> Vec<u8> {
        let mut out = Vec::new();
        let mut bits = 0u32;
        let mut count = 0;
        for byte in encoded.bytes().filter(|b| !b.is_ascii_whitespace()) {
            if byte == b'=' {
                break;
            }
            let value = match byte {
                b'A'..=b'Z' => byte - b'A',
                b'a'..=b'z' => byte - b'a' + 26,
                b'0'..=b'9' => byte - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                _ => panic!("invalid base64"),
            };
            bits = (bits << 6) | u32::from(value);
            count += 6;
            if count >= 8 {
                count -= 8;
                out.push((bits >> count) as u8);
            }
        }
        out
    }

    #[test]
    fn valid_replies_and_fragmented_multiline() {
        for code in [220, 250, 251, 354, 421, 450, 550, 599] {
            for suffix in ["\r\n", " \r\n", " message\r\n"] {
                assert_eq!(parse(format!("{code}{suffix}").as_bytes()).unwrap(), code);
            }
        }
        assert_eq!(
            parse(b"250-first\r\n250-SECOND\tvalue\r\n250 last\r\n").unwrap(),
            250
        );
        let mut parser = Reply::default();
        for chunk in [b"250-hel".as_slice(), b"lo\r", b"\n250 ", b"ok\r"] {
            for byte in chunk {
                assert!(parser.push(*byte).unwrap().is_none());
            }
        }
        assert_eq!(parser.push(b'\n').unwrap(), Some(250));
    }

    #[test]
    fn malformed_replies_are_sanitized() {
        for bytes in [
            b"".as_slice(),
            b"250 incomplete",
            b"250 x\n",
            b"250 x\rX\n",
            b"25 ok\r\n",
            b"25x ok\r\n",
            b"x50 ok\r\n",
            b"150 ok\r\n",
            b"600 ok\r\n",
            b"250!ok\r\n",
            b"250 \0secret\r\n",
            b"250 \x7fsecret\r\n",
            b"250 \xffsecret\r\n",
            b"250-first\r\n251 last\r\n",
            b"250-first\r\n550 secret\r\n",
            b"250-unfinished\r\n",
            b"\r\n",
            b"250 x\r\r\n",
        ] {
            assert!(
                matches!(parse(bytes), Err(Error::Transport(s)) if s == "SMTP transport or protocol failure")
            );
        }
    }

    #[test]
    fn reply_line_and_multiline_limits() {
        assert_eq!(
            parse(format!("250 {}\r\n", "x".repeat(506)).as_bytes()).unwrap(),
            250
        );
        assert!(parse(format!("250 {}\r\n", "x".repeat(507)).as_bytes()).is_err());
        assert!(parse(&vec![b'x'; 513]).is_err());
        assert_eq!(
            parse(format!("{}250 done\r\n", "250-\r\n".repeat(63)).as_bytes()).unwrap(),
            250
        );
        assert!(parse(format!("{}250 done\r\n", "250-\r\n".repeat(64)).as_bytes()).is_err());
        let long_line = format!("250-{}\r\n", "x".repeat(506));
        let exact_limit = format!("{}250 {}\r\n", long_line.repeat(31), "x".repeat(506));
        assert_eq!(exact_limit.len(), 16 * 1024);
        assert_eq!(parse(exact_limit.as_bytes()).unwrap(), 250);
        assert!(parse(format!("{}250 done\r\n", long_line.repeat(32)).as_bytes()).is_err());
    }

    #[test]
    fn only_negative_smtp_codes_are_rejections() {
        for code in [220, 250, 251, 354] {
            assert!(expected(code, &[code]).is_ok());
            assert!(matches!(expected(code, &[999]), Err(Error::Transport(_))));
        }
        for code in [400, 421, 450, 499, 500, 550, 599] {
            assert!(matches!(expected(code, &[250]), Err(Error::Rejected(n)) if n == code));
        }
    }

    #[test]
    fn strict_mailbox_validation() {
        for address in [
            "hello@example.test",
            "a.b+tag@sub.example.test",
            "a@localhost",
            "a!#$%&'*+-/=?^_`{|}~@example.test",
        ] {
            assert_eq!(mailbox(address).unwrap(), address);
        }
        for address in [
            "",
            "@example.test",
            "a@",
            "a@@example.test",
            "a b@example.test",
            " a@example.test",
            "a@example.test ",
            "a@example.test\r\nRCPT TO:<x@y>",
            "a@example.test\0",
            "a@example.test\t",
            "a@example.test SIZE=1",
            "<a@example.test>",
            "a@example.test,b@example.test",
            "a,b@example.test",
            "a<b@example.test",
            "\"a\"@example.test",
            "a(comment)@example.test",
            ".a@example.test",
            "a.@example.test",
            "a..b@example.test",
            "a@.test",
            "a@example..test",
            "a@example.test.",
            "a@-example.test",
            "a@example-.test",
            "a@exam_ple.test",
            "a@[127.0.0.1]",
            "\u{e9}@example.test",
            "a@ex\u{e4}mple.test",
        ] {
            assert!(
                matches!(mailbox(address), Err(Error::InvalidMessage(_))),
                "{address:?}"
            );
        }
        assert!(mailbox(&format!("{}@example.test", "a".repeat(64))).is_ok());
        assert!(mailbox(&format!("{}@example.test", "a".repeat(65))).is_err());
        assert!(mailbox(&format!("a@{}.test", "a".repeat(63))).is_ok());
        assert!(mailbox(&format!("a@{}.test", "a".repeat(64))).is_err());
        let domain = format!("{}.{}.{}", "b".repeat(63), "c".repeat(63), "d".repeat(61));
        let max = format!("{}@{domain}", "a".repeat(64));
        assert_eq!(max.len(), 254);
        assert!(mailbox(&max).is_ok());
        assert!(mailbox(&format!("{max}d")).is_err());
    }

    #[test]
    fn sender_display_and_envelope_injection() {
        assert_eq!(
            sender("Authentikate <hello@example.test>").unwrap(),
            ("hello@example.test", Some("Authentikate"))
        );
        assert_eq!(
            sender("hello@example.test").unwrap(),
            ("hello@example.test", None)
        );
        for from in [
            " <a@example.test>",
            " Name <a@example.test>",
            "Name  <a@example.test>",
            "Name <a@example.test> extra",
            "Name <a@example.test>>",
            "Name <a@example.test",
            "Name, Other <a@example.test>",
            "Name\r\nBcc: x@y <a@example.test>",
            "Name <a@example.test>\r\n",
            "Name <a@example.test> SIZE=0",
            "Name <a@example.test>, <b@example.test>",
            "\"Name\" <a@example.test>",
        ] {
            let mut email = message();
            email.from = from.into();
            assert!(prepare(&email).is_err(), "{from:?}");
        }
        let mut email = message();
        email.to[0] = "Other <other@example.test>".into();
        assert!(prepare(&email).is_err());
        email = message();
        email.subject = "subject\r\nBcc: other@example.test".into();
        assert!(prepare(&email).is_err());
    }

    #[test]
    fn base64_known_vectors() {
        for (input, encoded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64(input.as_bytes()), encoded);
        }
        let bytes: Vec<u8> = (0..=255).collect();
        assert_eq!(decode(&base64(&bytes)), bytes);
    }

    #[test]
    fn normalization_preserves_content_except_line_endings() {
        for (input, normalized) in [
            ("a\nb\rc\r\nd", "a\r\nb\r\nc\r\nd"),
            ("\r\r\n\n", "\r\n\r\n\r\n"),
            ("no newline", "no newline"),
            ("\u{e9}\n", "\u{e9}\r\n"),
        ] {
            assert_eq!(normalize(input), normalized.as_bytes());
        }
    }

    #[test]
    fn utf8_encoded_words_round_trip_without_split_characters() {
        for text in [
            "plain ASCII".to_string(),
            "x".repeat(500),
            format!("{}{}", "a".repeat(44), "\u{1f642}\u{e9}\u{4e2d}".repeat(40)),
        ] {
            let mut encoded = String::new();
            encoded_words(&text, &mut encoded);
            let mut decoded = String::new();
            for line in encoded.strip_prefix("\r\n").unwrap().split("\r\n") {
                let word = line.strip_prefix(' ').unwrap();
                assert!(word.len() <= 75);
                let content = word
                    .strip_prefix("=?UTF-8?B?")
                    .unwrap()
                    .strip_suffix("?=")
                    .unwrap();
                let chunk = decode(content);
                assert!(chunk.len() <= 45);
                decoded.push_str(std::str::from_utf8(&chunk).unwrap());
            }
            assert_eq!(decoded, text);
        }
    }

    #[test]
    fn mime_wire_format_is_seven_bit_and_data_safe() {
        let mut email = message();
        email.text = "\u{e9}\r\n.\r\n..\nQUIT\r\n\r\n\0end".into();
        let prepared = prepare(&email).unwrap();
        assert_eq!(prepared.from, "hello@example.test");
        assert_eq!(prepared.to, ["first@example.test", "second@example.test"]);
        let data = prepared.data;
        assert!(data.starts_with("From:\r\n =?UTF-8?B?QXV0aGVudGlrYXRl?=\r\n <hello@example.test>\r\nTo:\r\n <first@example.test>,\r\n <second@example.test>\r\nSubject:\r\n "));
        assert!(data.contains(
            "Content-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n"
        ));
        assert!(data.is_ascii());
        assert_eq!(data.matches("\r\n.\r\n").count(), 1);
        let (_, body) = data.split_once("\r\n\r\n").unwrap();
        let body = body.strip_suffix(".\r\n").unwrap();
        assert_eq!(decode(body), normalize(&email.text));
        assert!(body
            .split("\r\n")
            .all(|line| line.len() <= 76 && !line.starts_with('.')));
        assert!(!data.replace("\r\n", "").contains(['\r', '\n']));
        assert!(!data.contains("welcome-123"));
    }

    #[test]
    fn folds_long_headers_and_fifty_recipients() {
        let mut email = message();
        let domain = format!("{}.{}.{}", "b".repeat(63), "c".repeat(63), "d".repeat(61));
        let address = format!("{}@{domain}", "a".repeat(64));
        email.from = format!("{} <{address}>", "Name ".repeat(100).trim());
        email.to = vec![address; 50];
        email.subject = "\u{1f642}".repeat(1000);
        email.text = "x".repeat(1000);
        let data = prepare(&email).unwrap().data;
        assert!(data.split("\r\n").all(|line| line.len() <= 998));
        assert_eq!(data.matches(">,\r\n").count(), 49);
        email.to.push("other@example.test".into());
        assert!(prepare(&email).is_err());
    }

    #[test]
    fn shared_cap_and_optional_idempotency_validation() {
        let mut email = message();
        email.idempotency_key = None;
        assert!(prepare(&email).is_ok());
        for key in ["", "has space", "bad\r\nkey", "\u{e9}", &"k".repeat(256)] {
            email.idempotency_key = Some(key.into());
            assert!(prepare(&email).is_err());
        }
        email.idempotency_key = Some("k".repeat(255));
        let headers = email.from.len()
            + email.to.iter().map(String::len).sum::<usize>()
            + email.subject.len();
        email.text = "x".repeat(1024 * 1024 - headers);
        assert!(prepare(&email).is_ok());
        email.text.push('x');
        assert!(matches!(prepare(&email), Err(Error::InvalidMessage(_))));
    }
}
