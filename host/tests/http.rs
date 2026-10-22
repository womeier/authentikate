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
    fn start(stdout: Stdio) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_authentikate-host"))
            .current_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/.."))
            .env("LISTEN", "127.0.0.1:0")
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
        serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap()
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
    let mut server = Server::start(Stdio::piped());
    let (status, page) = server.raw(&format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        server.address
    ));
    assert_eq!(status, 200);
    assert!(page.contains("Identity Workbench"));
    for target in ["//rebound.test/", "http://rebound.test/"] {
        assert_eq!(
            server
                .raw(&format!(
                    "GET {target} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                    server.address
                ))
                .0,
            400
        );
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

#[cfg(target_os = "linux")]
#[test]
fn stdout_failure_preserves_account() {
    let full = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .unwrap();
    let server = Server::start(full.into());
    let credentials = json!({"email":"stored@example.test", "password":"test-password"});
    server.post("/api/signup", credentials.clone(), 500);
    server.post("/api/signup", credentials.clone(), 409);
    let login = server.post("/api/login", credentials, 200);
    assert_eq!(
        server.post("/api/validate", json!({"token":login["token"]}), 200)["valid"],
        true
    );
}
