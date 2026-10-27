use serde_json::{Value, json};
use std::{
    io::{self, BufRead, BufReader, Read, Write},
    net::{Shutdown, SocketAddr, TcpStream},
    process::{Child, ChildStderr, Command, Stdio},
    time::{Duration, Instant},
};

struct Server {
    child: Child,
    address: SocketAddr,
    _stderr: BufReader<ChildStderr>,
}

impl Server {
    fn start(stdout: Stdio, storage: &std::path::Path) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_authentikate-host"))
            .current_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/.."))
            .env("LISTEN", "127.0.0.1:0")
            .env("STORAGE_DIR", storage)
            .env_remove("PUBLIC_ORIGIN")
            .env_remove("HOST_COMPONENT")
            .env("SIGNUP_EMAIL_FROM", "Authentikate <test@example.test>")
            .stdout(stdout)
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut line = String::new();
        let mut stderr = BufReader::new(child.stderr.take().unwrap());
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let result = stderr.read_line(&mut line);
            let _ = tx.send((result, line, stderr));
        });
        let (result, line, stderr) =
            rx.recv_timeout(Duration::from_secs(60))
                .unwrap_or_else(|error| {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("Server startup: {error}");
                });
        result.unwrap();
        let address = line
            .trim()
            .strip_prefix("Authentikate demo: http://")
            .unwrap_or_else(|| panic!("Server did not start: {line}"))
            .parse()
            .unwrap();
        Self {
            child,
            address,
            _stderr: stderr,
        }
    }

    fn connect(&self) -> TcpStream {
        let socket = TcpStream::connect_timeout(&self.address, Duration::from_secs(5)).unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket
    }

    fn raw(&self, request: &str) -> (u16, String) {
        let mut socket = self.connect();
        socket.write_all(request.as_bytes()).unwrap();
        let response = read_response(&mut socket, Duration::from_secs(30)).unwrap();
        let status = response.split_whitespace().nth(1).unwrap().parse().unwrap();
        (status, response)
    }

    fn post(&self, path: &str, body: Value, expected: u16) -> Value {
        let body = body.to_string();
        let (status, response) = self.raw(&format!(
            "POST {path} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            self.address, body.len()
        ));
        assert_eq!(status, expected, "{response}");
        assert!(
            !response
                .to_lowercase()
                .contains("access-control-allow-origin")
        );
        serde_json::from_str(&payload(&response)).unwrap()
    }
}

// Bound the whole read, not just each individual socket operation.
fn read_response(socket: &mut TcpStream, timeout: Duration) -> io::Result<String> {
    let deadline = Instant::now() + timeout;
    let mut response = Vec::new();
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "HTTP response deadline"))?;
        socket.set_read_timeout(Some(remaining))?;
        let mut buffer = [0; 4096];
        match socket.read(&mut buffer) {
            Ok(0) => return Ok(String::from_utf8(response).unwrap()),
            Ok(n) => response.extend_from_slice(&buffer[..n]),
            Err(error) if error.kind() == io::ErrorKind::ConnectionReset && response.is_empty() => {
                return Ok(String::new());
            }
            Err(error) => return Err(error),
        }
    }
}

/// Take the body out of a raw response.
///
/// The component writes its body as a stream, so hyper frames these responses
/// with `Transfer-Encoding: chunked` rather than a `Content-Length` -- the old
/// Axum host knew the length up front and this one does not.
fn payload(response: &str) -> String {
    let (head, rest) = response.split_once("\r\n\r\n").unwrap();
    if !head.to_lowercase().contains("transfer-encoding: chunked") {
        return rest.to_owned();
    }
    let mut body = String::new();
    let mut rest = rest;
    loop {
        let (size, tail) = rest.split_once("\r\n").expect("chunk size line");
        let size = usize::from_str_radix(size.trim().split(';').next().unwrap(), 16)
            .expect("hexadecimal chunk size");
        if size == 0 {
            return body;
        }
        body.push_str(&tail[..size]);
        rest = &tail[size + 2..];
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn real_http_and_stdout_email() {
    let storage = tempfile::tempdir().unwrap();
    let mut server = Server::start(Stdio::piped(), storage.path());
    let (status, page) = server.raw(&format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        server.address
    ));
    assert_eq!(status, 200);
    assert!(page.contains("<title>Authentikate / Authentication Demo</title>"));
    // P3 splits scheme/authority/path; even an approved absolute authority
    // must not make the original absolute-form target acceptable.
    for target in [
        "//rebound.test/".to_owned(),
        "http://rebound.test/".to_owned(),
        format!("http://{}/", server.address),
        format!("https://{}/", server.address),
    ] {
        let (status, response) = server.raw(&format!(
            "GET {target} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            server.address
        ));
        assert_eq!(status, 400, "{target}: {response}");
    }
    assert_eq!(
        server
            .raw("GET / HTTP/1.1\r\nHost: rebound.test\r\nConnection: close\r\n\r\n")
            .0,
        403
    );
    assert_eq!(server.raw(&format!("POST /api/login HTTP/1.1\r\nHost: {}\r\nOrigin: https://untrusted.test\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}", server.address)).0, 403);
    // No Content-Length: verify that the limit also applies to chunked bodies.
    let oversized = "x".repeat(16385);
    assert_eq!(server.raw(&format!("POST /api/login HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: 16385\r\nConnection: close\r\n\r\n", server.address)).0, 413);
    assert_eq!(server.raw(&format!("POST /api/login HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n{oversized}\r\n0\r\n\r\n", server.address, oversized.len())).0, 413);
    let credentials = json!({"email":"socket@example.test", "password":"not-printed-password"});
    server.post("/api/signup", credentials.clone(), 201);
    server.post("/api/signup", credentials.clone(), 409);
    let login = server.post("/api/login", credentials, 200);
    assert_eq!(
        server.post("/api/validate", json!({"token":login["token"]}), 200)["valid"],
        true
    );
    server.child.kill().unwrap();
    server.child.wait().unwrap();
    let mut stdout = String::new();
    server
        .child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut stdout)
        .unwrap();
    let emails: Vec<Value> = stdout
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(
        emails,
        vec![json!({"backend":"stdout", "email":{
            "from":"Authentikate <test@example.test>", "to":["socket@example.test"],
            "subject":"Welcome to Authentikate", "text":"Your Authentikate account has been created."
        }})]
    );
    assert!(!stdout.contains("not-printed-password"));
}

#[test]
fn chunked_body_limit_counts_bytes_without_content_length() {
    let storage = tempfile::tempdir().unwrap();
    let server = Server::start(Stdio::null(), storage.path());
    // Invalid JSON fails immediately in the service, avoiding coupling this
    // gateway boundary test to the service's large-JSON parsing budget.
    let (status, invalid) = server.raw(&format!(
        "POST /api/signup HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx",
        server.address
    ));
    assert_eq!(status, 400, "{invalid}");
    for size in [16 * 1024, 16 * 1024 + 1] {
        let body = "x".repeat(size);
        // Split across chunks so the limit must count cumulative bytes. The
        // oversized request deliberately never finishes its chunked body.
        let (first, last) = body.split_at(8192);
        let end = if size == 16 * 1024 { "0\r\n\r\n" } else { "" };
        let (status, response) = server.raw(&format!(
            "POST /api/signup HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n{first}\r\n{:x}\r\n{last}\r\n{end}",
            server.address, first.len(), last.len()
        ));
        assert_eq!(
            status,
            if size == 16 * 1024 { 400 } else { 413 },
            "{response}"
        );
        if size == 16 * 1024 {
            assert_eq!(payload(&response), payload(&invalid));
        }
    }
}

#[test]
fn stalled_body_hits_fifteen_second_deadline() {
    let storage = tempfile::tempdir().unwrap();
    let server = Server::start(Stdio::null(), storage.path());
    let mut socket = server.connect();
    let started = Instant::now();
    socket.write_all(format!(
        "POST /api/signup HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n1\r\n{{\r\n",
        server.address
    ).as_bytes()).unwrap();
    // Keep the write side open: only the gateway's deadline can finish this.
    let response = read_response(&mut socket, Duration::from_secs(22)).unwrap();
    assert_eq!(
        response.split_whitespace().nth(1),
        Some("408"),
        "{response}"
    );
    assert!(started.elapsed() >= Duration::from_secs(15));
    assert_eq!(payload(&response), r#"{"error":"Request body timed out"}"#);
}

#[test]
fn truncated_body_does_not_invoke_signup() {
    let storage = tempfile::tempdir().unwrap();
    let server = Server::start(Stdio::null(), storage.path());
    for chunked in [false, true] {
        let credentials = json!({"email":format!("truncated-{chunked}@example.test"), "password":"test-password"});
        let body = credentials.to_string();
        let framing = if chunked {
            "Transfer-Encoding: chunked".to_owned()
        } else {
            format!("Content-Length: {}", body.len() + 1)
        };
        let wire_body = if chunked {
            format!("{:x}\r\n{body}\r\n", body.len())
        } else {
            body
        };
        let mut socket = server.connect();
        socket.write_all(format!(
            "POST /api/signup HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\n{framing}\r\nConnection: close\r\n\r\n{wire_body}",
            server.address
        ).as_bytes()).unwrap();
        socket.shutdown(Shutdown::Write).unwrap();
        let response = read_response(&mut socket, Duration::from_secs(5)).unwrap();
        // Hyper may close on a framing error before a response can be sent.
        if !response.is_empty() {
            assert_eq!(
                response.split_whitespace().nth(1),
                Some("400"),
                "{response}"
            );
        }
        // The bytes received were valid signup JSON: accepting EOF as success
        // would create the account and turn this into a conflict.
        server.post("/api/signup", credentials, 201);
    }
}

#[test]
fn early_rejection_does_not_wait_for_unconsumed_body() {
    let storage = tempfile::tempdir().unwrap();
    let server = Server::start(Stdio::null(), storage.path());
    for (headers, expected) in [
        (
            "Origin: https://untrusted.test\r\nTransfer-Encoding: chunked",
            403,
        ),
        (
            "Content-Type: text/plain\r\nTransfer-Encoding: chunked",
            415,
        ),
        (
            "Content-Type: application/json\r\nContent-Length: 16385",
            413,
        ),
    ] {
        let mut socket = server.connect();
        socket.write_all(format!(
            "POST /api/signup HTTP/1.1\r\nHost: {}\r\n{headers}\r\nConnection: close\r\n\r\n",
            server.address
        ).as_bytes()).unwrap();
        // Neither send the promised body nor half-close the connection.
        let response = read_response(&mut socket, Duration::from_secs(5)).unwrap();
        assert_eq!(
            response
                .split_whitespace()
                .nth(1)
                .unwrap()
                .parse::<u16>()
                .unwrap(),
            expected,
            "{response}"
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn stdout_failure_preserves_account() {
    let full = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .unwrap();
    let storage = tempfile::tempdir().unwrap();
    let server = Server::start(full.into(), storage.path());
    let credentials = json!({"email":"stored@example.test", "password":"test-password"});
    server.post("/api/signup", credentials.clone(), 500);
    server.post("/api/signup", credentials.clone(), 409);
    let login = server.post("/api/login", credentials, 200);
    assert_eq!(
        server.post("/api/validate", json!({"token":login["token"]}), 200)["valid"],
        true
    );
}

#[test]
fn accounts_survive_host_restart_but_tokens_do_not() {
    let storage = tempfile::tempdir().unwrap();
    let credentials = json!({"email":"restart@example.test", "password":"persistent-password"});
    let first = Server::start(Stdio::null(), storage.path());
    first.post("/api/signup", credentials.clone(), 201);
    let old = first.post("/api/login", credentials.clone(), 200);
    drop(first);
    let second = Server::start(Stdio::null(), storage.path());
    second.post("/api/signup", credentials.clone(), 409);
    let new = second.post("/api/login", credentials, 200);
    assert_eq!(
        second.post("/api/validate", json!({"token":new["token"]}), 200)["valid"],
        true
    );
    assert_eq!(
        second.post("/api/validate", json!({"token":old["token"]}), 200)["valid"],
        false
    );
}
