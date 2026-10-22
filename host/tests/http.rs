use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpStream},
    process::{Child, ChildStderr, Command, Stdio},
    time::Duration,
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
        stderr.read_line(&mut line).unwrap();
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

    fn raw(&self, request: &str) -> (u16, String) {
        let mut socket = TcpStream::connect(self.address).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        socket.write_all(request.as_bytes()).unwrap();
        let mut response = String::new();
        socket.read_to_string(&mut response).unwrap();
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
    assert!(page.contains("Identity Workbench"));
    // A protocol-relative target still reaches the gateway as a path and is
    // refused as not origin-form.  Absolute-form is different now: wasi-http
    // takes the authority from the URI in preference to the Host header, so
    // `http://rebound.test/` arrives as authority `rebound.test` and the
    // Host/Origin policy refuses it.  Both are refusals; the status differs
    // because the check that fires differs.
    assert_eq!(
        server
            .raw(&format!(
                "GET //rebound.test/ HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                server.address
            ))
            .0,
        400
    );
    assert_eq!(
        server
            .raw(&format!(
                "GET http://rebound.test/ HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                server.address
            ))
            .0,
        403
    );
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
