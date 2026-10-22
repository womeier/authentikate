//! The host: an engine, a socket, a storage preopen, and configuration.
//!
//! Everything request-shaped moved into `components/gateway`.  What is left
//! is the part that cannot be a per-request component instance: the Wasmtime
//! engine and its limits, admission control, the storage directory, and the
//! signing seed and origin policy the operator
//! configured.  The host no longer routes, serves assets, sets response
//! headers, decides a request's method or media type, or calls the service's
//! `login`/`validate`/`signup` directly -- it hands the composed component an
//! `incoming-request` and writes back whatever response it produces.

use anyhow::{Context, Result, ensure};
use http_body_util::BodyExt;
use hyper::{server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::Semaphore;
use wasmtime::{
    Engine, Store, StoreLimits, StoreLimitsBuilder,
    component::{Component, Linker, ResourceTable},
};
use wasmtime_wasi::{FsPerms, WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};
use wasmtime_wasi_http::{
    WasiHttpCtx, WasiHttpCtxView, WasiHttpHooks, WasiHttpView,
    p2::{bindings::http::types::Scheme, body::HyperOutgoingBody},
};
use zeroize::Zeroizing;

mod bindings {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}
#[cfg(test)]
mod storage_tests;
use bindings::{
    WebHost,
    authentikate::config::{policy, service as service_config},
};

/// Everything the host configures, in the shape it hands out.  Split in two on
/// the way to the guests: the seed goes only to the service, the origin rules
/// only to the gateway.
#[derive(Clone)]
struct Settings {
    service: service_config::Settings,
    policy: policy::Rules,
}

const FUEL: u64 = 2_000_000_000;

/// No outbound HTTP.  `wasmtime-wasi-http` is built without
/// `default-send-request`, so there is no `send_request` to override and no
/// code path that could issue one; the composed artifact imports no
/// `wasi:http/outgoing-handler` either, and `Runtime::new` rejects one that
/// does.  Every hook here is upstream's default.
struct NoOutboundHttp;

impl WasiHttpHooks for NoOutboundHttp {
    /// Refuse, rather than inherit a sending implementation.  Nothing in the
    /// composed artifact can reach this -- it imports no
    /// `wasi:http/outgoing-handler`, and `Runtime::new` rejects one that does
    /// -- so this is the statement that the refusal is deliberate and not an
    /// unbuilt default.
    fn send_request(
        &mut self,
        _request: hyper::Request<wasmtime_wasi_http::p2::body::HyperOutgoingBody>,
        _options: Option<wasmtime_wasi_http::RequestOptions>,
        _between_bytes_timeout: Box<
            dyn std::future::Future<Output = Result<(), wasmtime_wasi_http::Error>> + Send,
        >,
    ) -> Box<
        dyn std::future::Future<
                Output = Result<
                    (
                        hyper::Response<wasmtime_wasi_http::p2::body::HyperOutgoingBody>,
                        Box<
                            dyn std::future::Future<Output = Result<(), wasmtime_wasi_http::Error>>
                                + Send,
                        >,
                    ),
                    wasmtime_wasi_http::Error,
                >,
            > + Send,
    > {
        Box::new(std::future::ready(Err(
            wasmtime_wasi_http::Error::HttpRequestDenied,
        )))
    }
}

struct GuestState {
    wasi: WasiCtx,
    http: WasiHttpCtx,
    hooks: NoOutboundHttp,
    table: ResourceTable,
    settings: Settings,
    limits: StoreLimits,
}

impl WasiView for GuestState {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
}

impl WasiHttpView for GuestState {
    fn http(&mut self) -> WasiHttpCtxView<'_> {
        WasiHttpCtxView {
            hooks: &mut self.hooks,
            ctx: &mut self.http,
            table: &mut self.table,
        }
    }
}

/// The service's configuration, read once per request by its adapter -- the
/// signing seed, the issuer, the TTL and the sender address.  The gateway does
/// not import this interface, so the seed reaches only the component that
/// signs with it.
impl service_config::Host for GuestState {
    fn get(&mut self) -> wasmtime::Result<service_config::Settings> {
        Ok(self.settings.service.clone())
    }
}

/// The gateway's configuration: the approved origin, or the authorities this
/// process is actually listening on.  Both are host knowledge -- `LISTEN`
/// picks the port at runtime -- while the rule applied to them is the
/// gateway's.  A typed interface rather than `wasi:cli/environment`, which
/// would be read access to every variable in the process.
impl policy::Host for GuestState {
    fn get(&mut self) -> wasmtime::Result<policy::Rules> {
        Ok(self.settings.policy.clone())
    }
}

struct Runtime {
    engine: Engine,
    component: Component,
    linker: Linker<GuestState>,
    storage: PathBuf,
    settings: Settings,
}

impl Runtime {
    fn new(path: &str, settings: Settings, storage: &Path) -> Result<Self> {
        let mut options = wasmtime::Config::new();
        options.consume_fuel(true);
        let engine = Engine::new(&options)?;
        let component = Component::from_file(&engine, path)
            .map_err(anyhow::Error::from)
            .with_context(|| format!("Load {path}; build it with make host-component (or make compose-host for existing artifacts)"))?;
        // Refuse artifacts that ask the host for capabilities it does not mean
        // to grant.  The list is deliberately exhaustive: a composed artifact
        // that wants arbitrary network or environment access is not the
        // one this host was written for, whatever else it does correctly.
        for (name, _) in component.component_type().imports(&engine) {
            let (interface, version) = name.split_once('@').unwrap_or((name, ""));
            let wasi = [
                "wasi:clocks/wall-clock",
                "wasi:clocks/monotonic-clock",
                "wasi:random/random",
                "wasi:cli/stdout",
                "wasi:io/error",
                "wasi:io/poll",
                "wasi:io/streams",
                "wasi:http/types",
                "wasi:filesystem/types",
                "wasi:filesystem/preopens",
            ]
            .contains(&interface)
                && ["0.2.0", "0.2.4"].contains(&version);
            ensure!(
                [
                    "authentikate:config/service@0.1.0",
                    "authentikate:config/policy@0.1.0",
                ]
                .contains(&name)
                    || wasi,
                "Unexpected composed-component import: {name}"
            );
        }
        let mut linker = Linker::new(&engine);
        wasmtime_wasi::p2::add_to_linker_sync(&mut linker)?;
        wasmtime_wasi_http::p2::add_only_http_to_linker_sync(&mut linker)?;
        service_config::add_to_linker::<_, wasmtime::component::HasSelf<_>>(
            &mut linker,
            |state| state,
        )?;
        policy::add_to_linker::<_, wasmtime::component::HasSelf<_>>(&mut linker, |state| state)?;
        Ok(Self {
            engine,
            component,
            linker,
            storage: storage.to_path_buf(),
            settings,
        })
    }

    fn instantiate(&self) -> Result<(Store<GuestState>, WebHost)> {
        let state = GuestState {
            wasi: WasiCtxBuilder::new()
                .inherit_stdout()
                .preopened_dir(&self.storage, "/accounts", FsPerms::ReadWrite)?
                .build(),
            http: WasiHttpCtx::new(),
            hooks: NoOutboundHttp,
            table: ResourceTable::new(),
            settings: self.settings.clone(),
            limits: StoreLimitsBuilder::new()
                .memory_size(128 * 1024 * 1024)
                .memories(8)
                .instances(32)
                .tables(16)
                .build(),
        };
        let mut store = Store::new(&self.engine, state);
        store.limiter(|state| &mut state.limits);
        store.set_fuel(FUEL)?;
        let guest = WebHost::instantiate(&mut store, &self.component, &self.linker)?;
        Ok((store, guest))
    }

    /// Start one request on a fresh instance.
    ///
    /// This returns only once the guest has finished, which is *after* the
    /// response has gone out: the guest writes its body into a bounded
    /// channel, so `serve` has to take the response from `receiver` and let
    /// hyper drain that channel while this is still running.  Draining it
    /// afterwards would deadlock -- the guest blocks on the first chunk that
    /// does not fit.  Dropping the instance here is what reclaims the Rocq
    /// bump heap, and it happens only once the body is fully written.
    fn run<B>(
        &self,
        request: hyper::Request<B>,
        sender: tokio::sync::oneshot::Sender<
            Result<
                hyper::Response<HyperOutgoingBody>,
                wasmtime_wasi_http::p2::bindings::http::types::ErrorCode,
            >,
        >,
    ) -> Result<()>
    where
        B: hyper::body::Body<Data = hyper::body::Bytes> + Send + 'static,
        B::Error: Into<wasmtime_wasi_http::Error>,
    {
        let (mut store, guest) = self.instantiate()?;
        let incoming = store
            .data_mut()
            .http()
            .new_incoming_request(Scheme::Http, request)?;
        let outparam = store.data_mut().http().new_response_outparam(sender)?;
        guest
            .wasi_http_incoming_handler()
            .call_handle(&mut store, incoming, outparam)?;
        Ok(())
    }
}

struct App {
    runtime: Runtime,
    gate: Arc<Semaphore>,
    slots: Arc<Semaphore>,
}

fn unavailable(status: hyper::StatusCode, message: &str) -> hyper::Response<HyperOutgoingBody> {
    let body = format!("{{\"error\":\"{message}\"}}");
    hyper::Response::builder()
        .status(status)
        .header(
            hyper::header::CONTENT_TYPE,
            "application/json; charset=utf-8",
        )
        .header(hyper::header::CACHE_CONTROL, "no-store")
        .body(
            http_body_util::Full::new(body.into())
                .map_err(|never| match never {})
                .boxed_unsync(),
        )
        .unwrap()
}

/// Admission, then one request at a time inside the engine.
///
/// The two responses this host still writes itself are both refusals to run
/// the component at all, which is why they are here and not in the gateway.
async fn serve<B>(
    app: Arc<App>,
    request: hyper::Request<B>,
) -> Result<hyper::Response<HyperOutgoingBody>>
where
    B: hyper::body::Body<Data = hyper::body::Bytes> + Send + 'static,
    B::Error: Into<wasmtime_wasi_http::Error>,
{
    // Reject excess work instead of building an unbounded queue of password hashes.
    let Ok(slot) = app.slots.clone().try_acquire_owned() else {
        return Ok(unavailable(
            hyper::StatusCode::SERVICE_UNAVAILABLE,
            "Service busy; retry later",
        ));
    };
    let permit = app.gate.clone().acquire_owned().await.unwrap();
    let (sender, receiver) = tokio::sync::oneshot::channel();
    // The permit and the slot are released when the guest finishes, not when
    // the response is returned, so a streaming body still counts as work in
    // flight.  Dropping this handle does not cancel the task.
    let guest = {
        let app = app.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let _slot = slot;
            app.runtime.run(request, sender)
        })
    };
    match receiver.await {
        Ok(Ok(response)) => Ok(response),
        // The guest set the outparam to an error, or returned without setting
        // it at all -- the WIT forbids the latter, so both are broken guests.
        Ok(Err(_)) | Err(_) => {
            let _ = guest.await;
            Ok(unavailable(
                hyper::StatusCode::INTERNAL_SERVER_ERROR,
                "Component request failed",
            ))
        }
    }
}

/// Validate and normalize an approved origin: scheme plus authority, nothing
/// else.  The gateway compares against the result rather than parsing it
/// again, so this is the only place the shape is checked.
fn approved_origin(value: &str) -> Result<String> {
    let origin = url::Url::parse(value)?;
    ensure!(
        matches!(origin.scheme(), "http" | "https")
            && origin.host_str().is_some()
            && origin.username().is_empty()
            && origin.password().is_none()
            && origin.path() == "/"
            && origin.query().is_none()
            && origin.fragment().is_none(),
        "PUBLIC_ORIGIN must be an http(s) origin without credentials, path, query or fragment"
    );
    Ok(origin.origin().ascii_serialization())
}

/// The loopback authorities a browser may name when no origin is configured.
/// The port is known only after binding, which is why this is the host's job.
fn loopback_authorities(port: u16) -> Vec<String> {
    ["127.0.0.1", "localhost", "[::1]"]
        .iter()
        .map(|name| {
            if port == 80 {
                name.to_string()
            } else {
                format!("{name}:{port}")
            }
        })
        .collect()
}

fn configuration(port: u16, public_origin: Option<&str>) -> Result<Settings> {
    let mut key = Zeroizing::new([0u8; 32]);
    getrandom::fill(key.as_mut()).context("Generate HS256 key")?;
    let approved_origin = public_origin.map(approved_origin).transpose()?;
    Ok(Settings {
        service: service_config::Settings {
            signing_seed: key.to_vec(),
            iss: "demo".into(),
            ttl: 600,
            email_from: std::env::var("SIGNUP_EMAIL_FROM")
                .unwrap_or_else(|_| "Authentikate <hello@example.test>".into()),
        },
        policy: policy::Rules {
            approved_authorities: if approved_origin.is_some() {
                vec![]
            } else {
                loopback_authorities(port)
            },
            approved_origin,
        },
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    let listen: SocketAddr = std::env::var("LISTEN")
        .unwrap_or_else(|_| "127.0.0.1:3000".into())
        .parse()
        .context("LISTEN must be an IP address and port")?;
    let public_origin = std::env::var("PUBLIC_ORIGIN").ok();
    ensure!(
        listen.ip().is_loopback() || public_origin.is_some(),
        "Non-loopback LISTEN requires an explicit PUBLIC_ORIGIN"
    );
    let path =
        std::env::var("HOST_COMPONENT").unwrap_or_else(|_| "build/host.component.wasm".into());
    let listener = tokio::net::TcpListener::bind(listen).await?;
    let address = listener.local_addr()?;
    let settings = configuration(address.port(), public_origin.as_deref())?;
    let storage =
        PathBuf::from(std::env::var_os("STORAGE_DIR").unwrap_or_else(|| "accounts".into()));
    let mut directory = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        directory.mode(0o700);
    }
    match directory.create(&storage) {
        Ok(()) => (),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists && storage.is_dir() => (),
        Err(error) => return Err(error).context("Create STORAGE_DIR"),
    }
    let runtime = Runtime::new(&path, settings, &storage)?;
    eprintln!(
        "Authentikate demo: {}",
        public_origin.unwrap_or_else(|| format!("http://{address}"))
    );
    eprintln!(
        "Accounts persist in {}. The signing key is lost on restart. Welcome emails go to stdout.",
        storage.display()
    );
    let app = Arc::new(App {
        runtime,
        gate: Arc::new(Semaphore::new(1)),
        slots: Arc::new(Semaphore::new(8)),
    });
    loop {
        let (connection, _) = tokio::select! {
            accepted = listener.accept() => accepted?,
            _ = tokio::signal::ctrl_c() => break,
        };
        let app = app.clone();
        tokio::spawn(async move {
            let _ = http1::Builder::new()
                .keep_alive(true)
                .serve_connection(
                    TokioIo::new(connection),
                    service_fn(move |request| serve(app.clone(), request)),
                )
                .await;
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::Full;
    use hyper::{Method, StatusCode, body::Bytes, header};
    use serde_json::{Value, json};

    const COMPOSED: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../build/host.component.wasm");

    fn app(settings: Settings) -> (Arc<App>, tempfile::TempDir) {
        let storage = tempfile::tempdir().unwrap();
        let app = Arc::new(App {
            runtime: Runtime::new(COMPOSED, settings, storage.path()).unwrap(),
            gate: Arc::new(Semaphore::new(1)),
            slots: Arc::new(Semaphore::new(8)),
        });
        (app, storage)
    }

    fn demo() -> Settings {
        configuration(3000, None).unwrap()
    }

    /// Drive one request through the real `serve` path -- admission, a fresh
    /// instance, and the composed component -- without a socket.
    async fn request(
        app: &Arc<App>,
        method: Method,
        path: &str,
        body: &str,
        headers: &[(&str, &str)],
    ) -> (StatusCode, Vec<u8>) {
        let mut builder = hyper::Request::builder()
            .method(method)
            .uri(path)
            .header(header::HOST, "127.0.0.1:3000");
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let request = builder
            .body(Full::new(Bytes::from(body.to_owned())))
            .unwrap();
        let response = serve(app.clone(), request).await.unwrap();
        let status = response.status();
        assert!(
            !response
                .headers()
                .contains_key("access-control-allow-origin"),
            "no permissive CORS header is ever emitted"
        );
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, body.to_vec())
    }

    async fn post(app: &Arc<App>, path: &str, body: Value, expected: StatusCode) -> Value {
        let (status, body) = request(
            app,
            Method::POST,
            path,
            &body.to_string(),
            &[(header::CONTENT_TYPE.as_str(), "application/json")],
        )
        .await;
        assert_eq!(status, expected, "{}", String::from_utf8_lossy(&body));
        serde_json::from_slice(&body).unwrap()
    }

    // Intentionally fails when the composed artifact is missing or stale.
    #[tokio::test(flavor = "multi_thread")]
    async fn composed_authentication_and_http_boundaries() {
        let (app, storage) = app(demo());

        for path in ["/", "/style.css", "/app.js"] {
            let request = hyper::Request::builder()
                .uri(path)
                .header(header::HOST, "127.0.0.1:3000")
                .body(Full::new(Bytes::new()))
                .unwrap();
            let response = serve(app.clone(), request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            assert!(
                response.headers()["content-security-policy"]
                    .to_str()
                    .unwrap()
                    .contains("default-src 'self'"),
                "{path}"
            );
            assert!(
                !response
                    .into_body()
                    .collect()
                    .await
                    .unwrap()
                    .to_bytes()
                    .is_empty(),
                "{path}"
            );
        }

        let json = [(header::CONTENT_TYPE.as_str(), "application/json")];
        for (method, path, body, headers, expected) in [
            (
                Method::GET,
                "/api/login",
                "",
                &json[..],
                StatusCode::METHOD_NOT_ALLOWED,
            ),
            (
                Method::GET,
                "/Cargo.toml",
                "",
                &[][..],
                StatusCode::NOT_FOUND,
            ),
            (
                Method::POST,
                "/api/no-route",
                "{}",
                &json[..],
                StatusCode::NOT_FOUND,
            ),
            (
                Method::POST,
                "/api/login",
                "{}",
                &[][..],
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ),
            (
                Method::POST,
                "/api/login",
                "{}",
                &[
                    (header::CONTENT_TYPE.as_str(), "application/json"),
                    (header::ORIGIN.as_str(), "https://untrusted.test"),
                ][..],
                StatusCode::FORBIDDEN,
            ),
        ] {
            let (status, _) = request(&app, method, path, body, headers).await;
            assert_eq!(status, expected, "{path}");
        }
        // Counted rather than trusted: no Content-Length is set here.
        let oversized = "x".repeat(16 * 1024 + 1);
        let (status, _) = request(&app, Method::POST, "/api/login", &oversized, &json).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);

        let credentials =
            json!({"email":"workbench@example.test", "password":"a-local-demo-password"});
        assert_eq!(
            post(
                &app,
                "/api/signup",
                credentials.clone(),
                StatusCode::CREATED
            )
            .await,
            json!({})
        );
        post(
            &app,
            "/api/signup",
            credentials.clone(),
            StatusCode::CONFLICT,
        )
        .await;
        let login = post(&app, "/api/login", credentials.clone(), StatusCode::OK).await;
        let token = login["token"].as_str().unwrap().to_owned();
        let validation = post(
            &app,
            "/api/validate",
            json!({"token": token}),
            StatusCode::OK,
        )
        .await;
        assert_eq!(validation["valid"], true);
        assert_eq!(validation["claims"]["sub"], credentials["email"]);
        assert_eq!(validation["claims"]["iss"], "demo");
        assert_eq!(
            validation["claims"]["exp"].as_u64().unwrap()
                - validation["claims"]["iat"].as_u64().unwrap(),
            600
        );
        post(
            &app,
            "/api/login",
            json!({"email":credentials["email"], "password":"wrong"}),
            StatusCode::UNAUTHORIZED,
        )
        .await;
        post(
            &app,
            "/api/login",
            json!({"email":"unknown@example.test", "password":"wrong"}),
            StatusCode::UNAUTHORIZED,
        )
        .await;

        let mut tampered = token.into_bytes();
        let signature = tampered.iter().rposition(|b| *b == b'.').unwrap() + 1;
        tampered[signature] = if tampered[signature] == b'A' {
            b'B'
        } else {
            b'A'
        };
        assert_eq!(
            post(
                &app,
                "/api/validate",
                json!({"token": String::from_utf8(tampered).unwrap()}),
                StatusCode::OK
            )
            .await,
            json!({"valid": false})
        );
        assert_eq!(
            post(
                &app,
                "/api/validate",
                json!({"token":"not.a.token"}),
                StatusCode::OK
            )
            .await,
            json!({"valid": false})
        );
        for endpoint in ["signup", "login", "validate"] {
            let path = format!("/api/{endpoint}");
            post(&app, &path, json!({}), StatusCode::BAD_REQUEST).await;
            let (status, _) = request(&app, Method::POST, &path, "{", &json).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{path}");
        }

        // Two signups for one email use atomic create; exactly one creates.
        let concurrent =
            json!({"email":"concurrent@example.test", "password":"a-local-demo-password"})
                .to_string();
        let (first, second) = tokio::join!(
            request(&app, Method::POST, "/api/signup", &concurrent, &json),
            request(&app, Method::POST, "/api/signup", &concurrent, &json)
        );
        let mut statuses = [first.0.as_u16(), second.0.as_u16()];
        statuses.sort();
        assert_eq!(statuses, [201, 409]);

        {
            let records: Vec<_> = std::fs::read_dir(storage.path())
                .unwrap()
                .map(|entry| entry.unwrap())
                .collect();
            assert_eq!(records.len(), 2);
            for entry in records {
                let bytes = std::fs::read(entry.path()).unwrap();
                assert_eq!(&bytes[..8], b"AKSTORE1");
                let length = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
                let record = &bytes[12 + length..];
                assert!(!String::from_utf8_lossy(record).contains("a-local-demo-password"));
                let record: Value = serde_json::from_slice(record).unwrap();
                assert_eq!(record["memory_kib"], 19456);
                assert!(record["salt"].as_str().is_some());
            }
        }

        let _full = app.slots.clone().acquire_many_owned(8).await.unwrap();
        let (status, _) = request(&app, Method::POST, "/api/login", "{}", &json).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    }

    /// A configured origin is enforced end to end, not just in `configuration`.
    #[tokio::test(flavor = "multi_thread")]
    async fn configured_origin_refuses_loopback() {
        let (app, _storage) = app(configuration(3000, Some("https://demo.example.test")).unwrap());
        let (status, _) = request(&app, Method::GET, "/", "", &[]).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let request = hyper::Request::builder()
            .uri("/")
            .header(header::HOST, "demo.example.test")
            .header(header::ORIGIN, "https://demo.example.test")
            .body(Full::new(Bytes::new()))
            .unwrap();
        assert_eq!(serve(app, request).await.unwrap().status(), StatusCode::OK);
    }

    // Argon2 has to run even when the account does not exist.  [login_check]
    // in Api.v hashes before it tests whether the lookup found anything, and
    // [login_check_none] in Proofs.v proves the answer is [Unauthorized]
    // either way -- which is exactly the licence a semantics-preserving
    // optimizer needs to delete the call, since timing is not in the
    // observable semantics it preserves.  Today the call survives because
    // CertiRocq has no pass that would drop it and wasm-opt is not asked to
    // optimize, but no proof in this repository rules it out and nothing else
    // here would fail if a toolchain bump started doing it.  Hence a
    // measurement, with a generous threshold: eliminating the hash drops the
    // absent path by orders of magnitude, not by a factor.
    #[tokio::test(flavor = "multi_thread")]
    async fn absent_account_still_pays_for_argon2() {
        let (app, _storage) = app(demo());
        let json = [(header::CONTENT_TYPE.as_str(), "application/json")];
        let enrolled = json!({"email":"timing@example.test","password":"a-local-demo-password"});
        post(&app, "/api/signup", enrolled, StatusCode::CREATED).await;
        let known = json!({"email":"timing@example.test","password":"wrong"}).to_string();
        let absent = json!({"email":"absent@example.test","password":"wrong"}).to_string();
        let sample = async |body: &str| {
            let start = std::time::Instant::now();
            let (status, _) = request(&app, Method::POST, "/api/login", body, &json).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
            start.elapsed()
        };
        // Interleaved and taken at the median, so that machine load drifting
        // under the test hits both paths alike.
        let (mut found, mut missing) = (Vec::new(), Vec::new());
        for _ in 0..5 {
            found.push(sample(&known).await);
            missing.push(sample(&absent).await);
        }
        found.sort();
        missing.sort();
        let (found, missing) = (found[2], missing[2]);
        assert!(
            found >= std::time::Duration::from_millis(1),
            "a wrong password against a stored record took {found:?}: the \
             comparison below has nothing to compare against, so the cost \
             parameters or the Argon2 provider are not doing the work"
        );
        assert!(
            missing * 4 >= found,
            "login for an absent account took {missing:?} against {found:?} for \
             a wrong password on a stored one: the dummy hash is not running, so \
             a login's duration discloses whether an account exists"
        );
    }

    /// A seed Ed25519 will refuse. The gateway used to catch this when it
    /// assembled `config`; now the service's adapter imports the key, so the
    /// 500 and its body are hand-written WebAssembly in
    /// `components/service/adapters/service.wat`. Nothing else exercises that
    /// branch, and it is the one place a bad configuration can reach.
    #[tokio::test]
    async fn a_rejected_signing_seed_is_a_clean_500() {
        let mut settings = demo();
        settings.service.signing_seed = vec![0u8; 31];
        let (app, _storage) = app(settings);
        let (status, body) = request(
            &app,
            Method::POST,
            "/api/login",
            "{\"email\":\"a@b.test\",\"password\":\"xxxxxxxxxxxx\"}",
            &[(header::CONTENT_TYPE.as_str(), "application/json")],
        )
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap(),
            json!({"error": "Service is misconfigured"})
        );
    }

    #[test]
    fn approved_origins_must_be_origins() {
        assert_eq!(
            approved_origin("https://demo.example.test").unwrap(),
            "https://demo.example.test"
        );
        assert_eq!(
            approved_origin("https://Demo.Example.Test/").unwrap(),
            "https://demo.example.test"
        );
        for value in [
            "ftp://example.test",
            "https://user@example.test",
            "https://example.test/path",
            "https://example.test?x",
            "https://example.test#x",
            "example.test",
        ] {
            assert!(approved_origin(value).is_err(), "{value}");
        }
    }

    #[test]
    fn loopback_authorities_follow_the_bound_port() {
        assert_eq!(
            loopback_authorities(3000),
            ["127.0.0.1:3000", "localhost:3000", "[::1]:3000"]
        );
        assert_eq!(
            loopback_authorities(80),
            ["127.0.0.1", "localhost", "[::1]"]
        );
    }

    /// An approved origin and the loopback allow-list are alternatives: with
    /// one configured, the gateway must not also accept `127.0.0.1`.
    #[test]
    fn configured_origin_replaces_the_loopback_list() {
        let settings = configuration(3000, Some("https://demo.example.test")).unwrap();
        assert_eq!(
            settings.policy.approved_origin.as_deref(),
            Some("https://demo.example.test")
        );
        assert!(settings.policy.approved_authorities.is_empty());
        let settings = configuration(3000, None).unwrap();
        assert!(settings.policy.approved_origin.is_none());
        assert_eq!(settings.policy.approved_authorities.len(), 3);
        assert_eq!(settings.service.signing_seed.len(), 32);
    }
}
