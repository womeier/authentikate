//! The host: an engine, a socket, a keyvalue provider, and configuration.
//!
//! Everything request-shaped moved into `components/gateway`.  What is left
//! is the part that cannot be a per-request component instance: the Wasmtime
//! engine and its limits, admission control, the account map that has to
//! outlive a request, and the signing seed and origin policy the operator
//! configured.  The host no longer routes, serves assets, sets response
//! headers, decides a request's method or media type, or calls the service's
//! `login`/`validate`/`signup` directly -- it hands the composed component an
//! `incoming-request` and writes back whatever response it produces.

use anyhow::{Context, Result, ensure};
use http_body_util::BodyExt;
use hyper::{server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
};
use tokio::sync::Semaphore;
use wasmtime::{
    Engine, Store, StoreLimits, StoreLimitsBuilder,
    component::{Component, Linker, Resource, ResourceTable},
};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};
use wasmtime_wasi_http::{
    WasiHttpCtx, WasiHttpCtxView, WasiHttpHooks, WasiHttpView,
    p2::{bindings::http::types::Scheme, body::HyperOutgoingBody},
};
use zeroize::Zeroizing;

mod bindings {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}
use bindings::{
    WebHost,
    authentikate::gateway::settings,
    wasi::keyvalue::{atomics, store as kv},
};

const FUEL: u64 = 2_000_000_000;
type Records = Arc<Mutex<BTreeMap<String, Vec<u8>>>>;
pub struct Bucket;

/// A compare-and-swap handle: the key it was opened on, and the value that
/// key held at the time.  `swap` writes only if the key still holds that
/// value, which is how the service creates an account without a window
/// between the read and the write.
pub struct Cas {
    key: String,
    seen: Option<Vec<u8>>,
}

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
                            dyn std::future::Future<
                                    Output = Result<(), wasmtime_wasi_http::Error>,
                                > + Send,
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
    records: Records,
    settings: settings::Config,
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

/// The configuration the gateway asks for, once per request.  A typed
/// interface rather than `wasi:cli/environment`: the component gets these six
/// values and no capability to read anything else in the process.
impl settings::Host for GuestState {
    fn get(&mut self) -> wasmtime::Result<settings::Config> {
        Ok(self.settings.clone())
    }
}

impl kv::Host for GuestState {
    fn open(
        &mut self,
        identifier: String,
    ) -> wasmtime::Result<Result<Resource<kv::Bucket>, kv::Error>> {
        if !identifier.is_empty() {
            return Ok(Err(kv::Error::NoSuchStore));
        }
        Ok(Ok(self.table.push(Bucket)?))
    }
}

impl kv::HostBucket for GuestState {
    fn get(
        &mut self,
        bucket: Resource<kv::Bucket>,
        key: String,
    ) -> wasmtime::Result<Result<Option<Vec<u8>>, kv::Error>> {
        self.table.get(&bucket)?;
        Ok(Ok(self.records.lock().unwrap().get(&key).cloned()))
    }
    fn set(
        &mut self,
        bucket: Resource<kv::Bucket>,
        key: String,
        value: Vec<u8>,
    ) -> wasmtime::Result<Result<(), kv::Error>> {
        self.table.get(&bucket)?;
        self.records.lock().unwrap().insert(key, value);
        Ok(Ok(()))
    }
    fn delete(
        &mut self,
        bucket: Resource<kv::Bucket>,
        key: String,
    ) -> wasmtime::Result<Result<(), kv::Error>> {
        self.table.get(&bucket)?;
        self.records.lock().unwrap().remove(&key);
        Ok(Ok(()))
    }
    fn exists(
        &mut self,
        bucket: Resource<kv::Bucket>,
        key: String,
    ) -> wasmtime::Result<Result<bool, kv::Error>> {
        self.table.get(&bucket)?;
        Ok(Ok(self.records.lock().unwrap().contains_key(&key)))
    }
    fn list_keys(
        &mut self,
        bucket: Resource<kv::Bucket>,
        cursor: Option<String>,
    ) -> wasmtime::Result<Result<kv::KeyResponse, kv::Error>> {
        self.table.get(&bucket)?;
        // draft2 cursors are keys, not offsets: resume strictly after the one
        // handed back.  The map is ordered, so this is the whole tail.
        let keys = self
            .records
            .lock()
            .unwrap()
            .keys()
            .filter(|key| cursor.as_ref().is_none_or(|from| *key > from))
            .cloned()
            .collect();
        Ok(Ok(kv::KeyResponse { keys, cursor: None }))
    }
    fn drop(&mut self, bucket: Resource<kv::Bucket>) -> wasmtime::Result<()> {
        self.table.delete(bucket)?;
        Ok(())
    }
}

impl atomics::HostCas for GuestState {
    fn new(
        &mut self,
        bucket: Resource<kv::Bucket>,
        key: String,
    ) -> wasmtime::Result<Result<Resource<atomics::Cas>, kv::Error>> {
        self.table.get(&bucket)?;
        let seen = self.records.lock().unwrap().get(&key).cloned();
        Ok(Ok(self.table.push(Cas { key, seen })?))
    }
    fn current(
        &mut self,
        cas: Resource<atomics::Cas>,
    ) -> wasmtime::Result<Result<Option<Vec<u8>>, kv::Error>> {
        Ok(Ok(self.table.get(&cas)?.seen.clone()))
    }
    fn drop(&mut self, cas: Resource<atomics::Cas>) -> wasmtime::Result<()> {
        self.table.delete(cas)?;
        Ok(())
    }
}

impl atomics::Host for GuestState {
    fn increment(
        &mut self,
        bucket: Resource<kv::Bucket>,
        key: String,
        delta: i64,
    ) -> wasmtime::Result<Result<i64, kv::Error>> {
        self.table.get(&bucket)?;
        let mut records = self.records.lock().unwrap();
        let counter: i64 = match records.get(&key) {
            None => 0,
            Some(value) => match std::str::from_utf8(value).ok().and_then(|v| v.parse().ok()) {
                Some(counter) => counter,
                None => return Ok(Err(kv::Error::Other("not a counter".into()))),
            },
        };
        let Some(next) = counter.checked_add(delta) else {
            return Ok(Err(kv::Error::Other("counter overflow".into())));
        };
        records.insert(key, next.to_string().into_bytes());
        Ok(Ok(next))
    }
    /// The whole point of the interface: the comparison and the write happen
    /// under one lock, so no other caller can land in between.  A swap that
    /// loses gets a fresh handle rather than an error, because upstream means
    /// it as an invitation to retry.
    fn swap(
        &mut self,
        cas: Resource<atomics::Cas>,
        value: Vec<u8>,
    ) -> wasmtime::Result<Result<(), atomics::CasError>> {
        let open = self.table.delete(cas)?;
        let mut records = self.records.lock().unwrap();
        let current = records.get(&open.key).cloned();
        if current != open.seen {
            drop(records);
            let retry = self.table.push(Cas {
                key: open.key,
                seen: current,
            })?;
            return Ok(Err(atomics::CasError::CasFailed(retry)));
        }
        records.insert(open.key, value);
        Ok(Ok(()))
    }
}

struct Runtime {
    engine: Engine,
    component: Component,
    linker: Linker<GuestState>,
    records: Records,
    settings: settings::Config,
}

impl Runtime {
    fn new(path: &str, settings: settings::Config) -> Result<Self> {
        let mut options = wasmtime::Config::new();
        options.consume_fuel(true);
        let engine = Engine::new(&options)?;
        let component = Component::from_file(&engine, path)
            .map_err(anyhow::Error::from)
            .with_context(|| format!("Load {path}; build it with make host-component (or make compose-host for existing artifacts)"))?;
        // Refuse artifacts that ask the host for capabilities it does not mean
        // to grant.  The list is deliberately exhaustive: a composed artifact
        // that wants the filesystem, the network or the environment is not the
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
            ]
            .contains(&interface)
                && ["0.2.0", "0.2.4"].contains(&version);
            ensure!(
                [
                    "wasi:keyvalue/store@0.2.0-draft2",
                    "wasi:keyvalue/atomics@0.2.0-draft2",
                    "authentikate:gateway/settings@0.1.0",
                ]
                .contains(&name)
                    || wasi,
                "Unexpected composed-component import: {name}"
            );
        }
        let mut linker = Linker::new(&engine);
        wasmtime_wasi::p2::add_to_linker_sync(&mut linker)?;
        wasmtime_wasi_http::p2::add_only_http_to_linker_sync(&mut linker)?;
        kv::add_to_linker::<_, wasmtime::component::HasSelf<_>>(&mut linker, |state| state)?;
        atomics::add_to_linker::<_, wasmtime::component::HasSelf<_>>(&mut linker, |state| state)?;
        settings::add_to_linker::<_, wasmtime::component::HasSelf<_>>(&mut linker, |state| state)?;
        Ok(Self {
            engine,
            component,
            linker,
            records: Records::default(),
            settings,
        })
    }

    fn instantiate(&self) -> Result<(Store<GuestState>, WebHost)> {
        let state = GuestState {
            wasi: WasiCtxBuilder::new().inherit_stdout().build(),
            http: WasiHttpCtx::new(),
            hooks: NoOutboundHttp,
            table: ResourceTable::new(),
            records: self.records.clone(),
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
            Result<hyper::Response<HyperOutgoingBody>, wasmtime_wasi_http::p2::bindings::http::types::ErrorCode>,
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
        .header(hyper::header::CONTENT_TYPE, "application/json; charset=utf-8")
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

fn configuration(port: u16, public_origin: Option<&str>) -> Result<settings::Config> {
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(seed.as_mut()).context("Generate signing seed")?;
    let approved_origin = public_origin.map(approved_origin).transpose()?;
    Ok(settings::Config {
        signing_seed: seed.to_vec(),
        issuer: "demo".into(),
        ttl: 600,
        email_from: std::env::var("SIGNUP_EMAIL_FROM")
            .unwrap_or_else(|_| "Authentikate <hello@example.test>".into()),
        approved_authorities: if approved_origin.is_some() {
            vec![]
        } else {
            loopback_authorities(port)
        },
        approved_origin,
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
    let runtime = Runtime::new(&path, settings)?;
    eprintln!(
        "Authentikate demo: {}",
        public_origin.unwrap_or_else(|| format!("http://{address}"))
    );
    eprintln!(
        "Ephemeral demo: accounts and signing key are lost on restart. Welcome emails go to stdout."
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

    fn app(settings: settings::Config) -> Arc<App> {
        Arc::new(App {
            runtime: Runtime::new(COMPOSED, settings).unwrap(),
            gate: Arc::new(Semaphore::new(1)),
            slots: Arc::new(Semaphore::new(8)),
        })
    }

    fn demo() -> settings::Config {
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
        let app = app(demo());
        let records = app.runtime.records.clone();

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
            (Method::GET, "/api/login", "", &json[..], StatusCode::METHOD_NOT_ALLOWED),
            (Method::GET, "/Cargo.toml", "", &[][..], StatusCode::NOT_FOUND),
            (Method::POST, "/api/no-route", "{}", &json[..], StatusCode::NOT_FOUND),
            (Method::POST, "/api/login", "{}", &[][..], StatusCode::UNSUPPORTED_MEDIA_TYPE),
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
            post(&app, "/api/signup", credentials.clone(), StatusCode::CREATED).await,
            json!({})
        );
        post(&app, "/api/signup", credentials.clone(), StatusCode::CONFLICT).await;
        let login = post(&app, "/api/login", credentials.clone(), StatusCode::OK).await;
        let token = login["token"].as_str().unwrap().to_owned();
        let validation = post(&app, "/api/validate", json!({"token": token}), StatusCode::OK).await;
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
        tampered[signature] = if tampered[signature] == b'A' { b'B' } else { b'A' };
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
            post(&app, "/api/validate", json!({"token":"not.a.token"}), StatusCode::OK).await,
            json!({"valid": false})
        );
        for endpoint in ["signup", "login", "validate"] {
            let path = format!("/api/{endpoint}");
            post(&app, &path, json!({}), StatusCode::BAD_REQUEST).await;
            let (status, _) = request(&app, Method::POST, &path, "{", &json).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{path}");
        }

        // Two signups for one email race through the CAS; exactly one creates.
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
            let records = records.lock().unwrap();
            assert_eq!(records.len(), 2);
            for record in records.values() {
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
        let app = app(configuration(3000, Some("https://demo.example.test")).unwrap());
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
        let app = app(demo());
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
        assert_eq!(loopback_authorities(80), ["127.0.0.1", "localhost", "[::1]"]);
    }

    /// An approved origin and the loopback allow-list are alternatives: with
    /// one configured, the gateway must not also accept `127.0.0.1`.
    #[test]
    fn configured_origin_replaces_the_loopback_list() {
        let settings = configuration(3000, Some("https://demo.example.test")).unwrap();
        assert_eq!(settings.approved_origin.as_deref(), Some("https://demo.example.test"));
        assert!(settings.approved_authorities.is_empty());
        let settings = configuration(3000, None).unwrap();
        assert!(settings.approved_origin.is_none());
        assert_eq!(settings.approved_authorities.len(), 3);
        assert_eq!(settings.signing_seed.len(), 32);
    }
}
