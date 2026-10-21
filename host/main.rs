use anyhow::{Context, Result, bail, ensure};
use axum::{
    Router,
    body::to_bytes,
    extract::{Request, State},
    http::{Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::Semaphore;
use wasmtime::{
    Engine, Store, StoreLimits, StoreLimitsBuilder,
    component::{Component, Linker, Resource, ResourceTable},
};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};
use zeroize::Zeroizing;

mod bindings {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}
use bindings::{
    WebHost,
    exports::authentikate::{
        crypto::argon2::Algorithm,
        service::api::{Argon2Params, Config},
    },
    wasi::keyvalue::store as kv,
};

const BODY_LIMIT: usize = 16 * 1024;
const FUEL: u64 = 2_000_000_000;
type Records = Arc<Mutex<BTreeMap<String, Vec<u8>>>>;
pub struct Bucket;

struct GuestState {
    wasi: WasiCtx,
    table: ResourceTable,
    records: Records,
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
        cursor: Option<u64>,
    ) -> wasmtime::Result<Result<kv::KeyResponse, kv::Error>> {
        self.table.get(&bucket)?;
        let keys = self
            .records
            .lock()
            .unwrap()
            .keys()
            .skip(cursor.unwrap_or(0) as usize)
            .cloned()
            .collect();
        Ok(Ok(kv::KeyResponse { keys, cursor: None }))
    }
    fn drop(&mut self, bucket: Resource<kv::Bucket>) -> wasmtime::Result<()> {
        self.table.delete(bucket)?;
        Ok(())
    }
}

struct Runtime {
    engine: Engine,
    component: Component,
    linker: Linker<GuestState>,
    records: Records,
    seed: Zeroizing<[u8; 32]>,
    config: Config,
}

impl Runtime {
    fn new(path: &str, email_from: String) -> Result<Self> {
        let mut options = wasmtime::Config::new();
        options.consume_fuel(true);
        let engine = Engine::new(&options)?;
        let component = Component::from_file(&engine, path)
            .map_err(anyhow::Error::from)
            .with_context(|| format!("Load {path}; build it with make host-component (or make compose-host for existing artifacts)"))?;
        // Refuse artifacts that ask the host to provide crypto or extra capabilities.
        for (name, _) in component.component_type().imports(&engine) {
            let (interface, version) = name.split_once('@').unwrap_or((name, ""));
            let wasi = [
                "wasi:clocks/wall-clock",
                "wasi:random/random",
                "wasi:cli/stdout",
                "wasi:io/error",
                "wasi:io/streams",
            ]
            .contains(&interface)
                && ["0.2.0", "0.2.4"].contains(&version);
            ensure!(
                name == "wasi:keyvalue/store@0.2.0-draft" || wasi,
                "Unexpected composed-component import: {name}"
            );
        }
        let mut linker = Linker::new(&engine);
        wasmtime_wasi::p2::add_to_linker_sync(&mut linker)?;
        kv::add_to_linker::<_, wasmtime::component::HasSelf<_>>(&mut linker, |state| state)?;
        let mut seed = Zeroizing::new([0; 32]);
        getrandom::fill(seed.as_mut()).context("Generate signing seed")?;
        let mut runtime = Self {
            engine,
            component,
            linker,
            records: Records::default(),
            seed,
            config: Config {
                key: 0,
                pubkey: vec![],
                iss: b"demo".to_vec(),
                ttl: 600,
                dummy_salt: vec![0; 16],
                dummy_tag: vec![],
                dummy_params: Argon2Params {
                    algorithm: 2,
                    memory_kib: 0,
                    iterations: 0,
                    parallelism: 0,
                    tag_length: 0,
                },
                email_from: email_from.into_bytes(),
            },
        };
        let (mut store, guest) = runtime.instantiate()?;
        let signer = guest.authentikate_crypto_ed25519();
        let key = signer.call_import_key(&mut store, runtime.seed.as_ref())??;
        runtime.config.pubkey = signer.call_public_key(&mut store, key)??;
        let argon = guest.authentikate_crypto_argon2();
        let params = argon.call_recommended_params(&mut store)?;
        getrandom::fill(&mut runtime.config.dummy_salt).context("Generate dummy salt")?;
        let mut password = Zeroizing::new([0; 32]);
        getrandom::fill(password.as_mut()).context("Generate dummy password")?;
        runtime.config.dummy_tag = argon.call_derive(
            &mut store,
            password.as_ref(),
            &runtime.config.dummy_salt,
            Algorithm::Argon2id,
            params,
        )??;
        runtime.config.dummy_params = Argon2Params {
            algorithm: 2,
            memory_kib: params.memory_kib,
            iterations: params.iterations,
            parallelism: params.parallelism,
            tag_length: params.tag_length,
        };
        Ok(runtime)
    }

    fn instantiate(&self) -> Result<(Store<GuestState>, WebHost)> {
        let state = GuestState {
            wasi: WasiCtxBuilder::new().inherit_stdout().build(),
            table: ResourceTable::new(),
            records: self.records.clone(),
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

    fn request(&self, operation: &str, body: &[u8]) -> Result<Response> {
        let (mut store, guest) = self.instantiate()?;
        let mut config = self.config.clone();
        // Provision exactly the signer instance connected to the service by WAC.
        config.key = guest
            .authentikate_crypto_ed25519()
            .call_import_key(&mut store, self.seed.as_ref())??;
        let api = guest.authentikate_service_api();
        let result = match operation {
            "signup" => api.call_signup(&mut store, &config, body)?,
            "login" => api.call_login(&mut store, &config, body)?,
            "validate" => api.call_validate(&mut store, &config, body)?,
            _ => bail!("Unknown service operation"),
        };
        let status = StatusCode::from_u16(result.status.try_into()?)?;
        Ok((
            status,
            [(header::CONTENT_TYPE, "application/json; charset=utf-8")],
            result.body,
        )
            .into_response())
    }
}

struct Policy {
    port: u16,
    public_origin: Option<url::Url>,
}

impl Policy {
    fn new(port: u16, public_origin: Option<&str>) -> Result<Self> {
        let public_origin = public_origin.map(url::Url::parse).transpose()?;
        if let Some(origin) = &public_origin {
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
        }
        Ok(Self {
            port,
            public_origin,
        })
    }

    fn permits(&self, request: &Request) -> bool {
        let hosts = request
            .headers()
            .get_all(header::HOST)
            .iter()
            .collect::<Vec<_>>();
        let [host] = hosts.as_slice() else {
            return false;
        };
        let Ok(host) = host.to_str() else {
            return false;
        };
        let expected_origin = if let Some(origin) = &self.public_origin {
            let authority = &origin[url::Position::BeforeHost..url::Position::AfterPort];
            if !host.eq_ignore_ascii_case(authority) {
                return false;
            }
            origin.origin().ascii_serialization()
        } else {
            let allowed = ["127.0.0.1", "localhost", "[::1]"].map(|name| {
                if self.port == 80 {
                    name.to_string()
                } else {
                    format!("{name}:{}", self.port)
                }
            });
            if !allowed.iter().any(|value| host.eq_ignore_ascii_case(value)) {
                return false;
            }
            format!("http://{}", host.to_ascii_lowercase())
        };
        let origins = request
            .headers()
            .get_all(header::ORIGIN)
            .iter()
            .collect::<Vec<_>>();
        origins.is_empty()
            || (origins.len() == 1 && origins[0].as_bytes() == expected_origin.as_bytes())
    }
}

struct App {
    runtime: Runtime,
    policy: Policy,
    gate: Arc<Semaphore>,
    slots: Arc<Semaphore>,
}

fn error(status: StatusCode, message: &str) -> Response {
    (status, axum::Json(serde_json::json!({"error": message}))).into_response()
}

async fn handle(State(app): State<Arc<App>>, request: Request) -> Response {
    let mut response = dispatch(app, request).await;
    let headers = response.headers_mut();
    for (name, value) in [
        ("cache-control", "no-store"),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"),
        (
            "content-security-policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
        ),
    ] {
        headers.insert(
            header::HeaderName::from_static(name),
            header::HeaderValue::from_static(value),
        );
    }
    response
}

async fn dispatch(app: Arc<App>, request: Request) -> Response {
    if request.uri().scheme().is_some()
        || request.uri().authority().is_some()
        || request.uri().path().starts_with("//")
    {
        return error(
            StatusCode::BAD_REQUEST,
            "Use an origin-form relative request target",
        );
    }
    if !app.policy.permits(&request) {
        return error(StatusCode::FORBIDDEN, "Host or Origin is not allowed");
    }
    let path = request.uri().path();
    let operation = match path {
        "/api/signup" => "signup",
        "/api/login" => "login",
        "/api/validate" => "validate",
        _ => {
            let asset = match path {
                "/" => Some((
                    "text/html; charset=utf-8",
                    include_str!("../web/index.html"),
                )),
                "/style.css" => Some(("text/css; charset=utf-8", include_str!("../web/style.css"))),
                "/app.js" => Some((
                    "text/javascript; charset=utf-8",
                    include_str!("../web/app.js"),
                )),
                _ => None,
            };
            return match asset {
                Some((kind, body)) if matches!(*request.method(), Method::GET | Method::HEAD) => (
                    [(header::CONTENT_TYPE, kind)],
                    if request.method() == Method::HEAD {
                        ""
                    } else {
                        body
                    },
                )
                    .into_response(),
                _ => error(StatusCode::NOT_FOUND, "Not found"),
            };
        }
    };
    if request.method() != Method::POST {
        let mut response = error(StatusCode::METHOD_NOT_ALLOWED, "Use POST");
        response
            .headers_mut()
            .insert(header::ALLOW, header::HeaderValue::from_static("POST"));
        return response;
    }
    if !request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|s| s.to_str().ok())
        .is_some_and(|s| {
            s.split(';')
                .next()
                .unwrap()
                .trim()
                .eq_ignore_ascii_case("application/json")
        })
    {
        return error(StatusCode::UNSUPPORTED_MEDIA_TYPE, "Use application/json");
    }
    if request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|s| s.to_str().ok()?.parse::<u64>().ok())
        .is_some_and(|length| length > BODY_LIMIT as u64)
    {
        return error(StatusCode::PAYLOAD_TOO_LARGE, "Request body exceeds 16 KiB");
    }
    let body = match tokio::time::timeout(
        Duration::from_secs(15),
        to_bytes(request.into_body(), BODY_LIMIT),
    )
    .await
    {
        Ok(Ok(body)) => body,
        Ok(Err(err)) => {
            use std::error::Error;
            let oversized = err
                .source()
                .is_some_and(|s| s.is::<http_body_util::LengthLimitError>());
            let status = if oversized {
                StatusCode::PAYLOAD_TOO_LARGE
            } else {
                StatusCode::BAD_REQUEST
            };
            return error(
                status,
                if status == StatusCode::PAYLOAD_TOO_LARGE {
                    "Request body exceeds 16 KiB"
                } else {
                    "Request interrupted"
                },
            );
        }
        Err(_) => return error(StatusCode::REQUEST_TIMEOUT, "Request body timed out"),
    };
    // Reject excess work instead of building an unbounded queue of password hashes.
    let Ok(slot) = app.slots.clone().try_acquire_owned() else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "Service busy; retry later");
    };
    let permit = app.gate.clone().acquire_owned().await.unwrap();
    match tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let _slot = slot;
        app.runtime.request(operation, &body)
    })
    .await
    {
        Ok(Ok(response)) => response,
        _ => error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Component request failed",
        ),
    }
}

fn router(app: Arc<App>) -> Router {
    Router::new().fallback(handle).with_state(app)
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
    let sender = std::env::var("SIGNUP_EMAIL_FROM")
        .unwrap_or_else(|_| "Authentikate <hello@example.test>".into());
    let runtime = Runtime::new(&path, sender)?;
    let listener = tokio::net::TcpListener::bind(listen).await?;
    let address = listener.local_addr()?;
    let policy = Policy::new(address.port(), public_origin.as_deref())?;
    eprintln!(
        "Authentikate demo: {}",
        public_origin.unwrap_or_else(|| format!("http://{address}"))
    );
    eprintln!(
        "Ephemeral demo: accounts and signing key are lost on restart. Welcome emails go to stdout."
    );
    let app = Arc::new(App {
        runtime,
        policy,
        gate: Arc::new(Semaphore::new(1)),
        slots: Arc::new(Semaphore::new(8)),
    });
    axum::serve(listener, router(app))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use serde_json::{Value, json};
    use tower::ServiceExt;

    fn request(method: Method, path: &str, body: impl Into<Body>) -> Request {
        Request::builder()
            .method(method)
            .uri(path)
            .header(header::HOST, "127.0.0.1:3000")
            .header(header::CONTENT_TYPE, "application/json")
            .body(body.into())
            .unwrap()
    }

    async fn post(app: &Router, path: &str, body: Value, expected: StatusCode) -> Value {
        let response = app
            .clone()
            .oneshot(request(Method::POST, path, body.to_string()))
            .await
            .unwrap();
        let status = response.status();
        assert!(
            !response
                .headers()
                .contains_key("access-control-allow-origin")
        );
        let body = to_bytes(response.into_body(), BODY_LIMIT).await.unwrap();
        assert_eq!(status, expected, "{}", String::from_utf8_lossy(&body));
        serde_json::from_slice(&body).unwrap()
    }

    #[test]
    fn host_and_origin_policy() {
        let policy = Policy::new(3000, None).unwrap();
        for (host, origin, expected) in [
            ("127.0.0.1:3000", None, true),
            ("localhost:3000", Some("http://localhost:3000"), true),
            ("[::1]:3000", Some("http://[::1]:3000"), true),
            ("rebound.test:3000", Some("http://rebound.test:3000"), false),
            ("127.0.0.1:1", None, false),
            ("127.0.0.1:3000", Some("https://untrusted.test"), false),
            ("127.0.0.1:3000", Some("null"), false),
        ] {
            let mut req = request(Method::GET, "/", "");
            req.headers_mut()
                .insert(header::HOST, host.parse().unwrap());
            if let Some(origin) = origin {
                req.headers_mut()
                    .insert(header::ORIGIN, origin.parse().unwrap());
            }
            assert_eq!(policy.permits(&req), expected, "{host} {origin:?}");
        }
        let policy = Policy::new(3000, Some("https://demo.example.test")).unwrap();
        let mut req = request(Method::GET, "/", "");
        assert!(!policy.permits(&req));
        req.headers_mut()
            .insert(header::HOST, "demo.example.test".parse().unwrap());
        req.headers_mut()
            .insert(header::ORIGIN, "https://demo.example.test".parse().unwrap());
        assert!(policy.permits(&req));
        req.headers_mut()
            .append(header::ORIGIN, "https://demo.example.test".parse().unwrap());
        assert!(!policy.permits(&req));
        for origin in [
            "ftp://example.test",
            "https://user@example.test",
            "https://example.test/path",
            "https://example.test?x",
            "https://example.test#x",
        ] {
            assert!(Policy::new(3000, Some(origin)).is_err(), "{origin}");
        }
    }

    // Intentionally fails when the composed artifact is missing or stale.
    #[tokio::test(flavor = "multi_thread")]
    async fn composed_authentication_and_http_boundaries() {
        let runtime = Runtime::new(
            "build/host.component.wasm",
            "Authentikate <hello@example.test>".into(),
        )
        .unwrap();
        assert_eq!(runtime.config.pubkey.len(), 32);
        assert_eq!(runtime.config.dummy_tag.len(), 32);
        assert_eq!(runtime.config.dummy_params.memory_kib, 19456);
        let records = runtime.records.clone();
        let gate = Arc::new(Semaphore::new(1));
        let slots = Arc::new(Semaphore::new(8));
        let app = router(Arc::new(App {
            runtime,
            policy: Policy::new(3000, None).unwrap(),
            gate: gate.clone(),
            slots: slots.clone(),
        }));
        for path in ["/", "/style.css", "/app.js"] {
            let response = app
                .clone()
                .oneshot(request(Method::GET, path, ""))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert!(
                response.headers()["content-security-policy"]
                    .to_str()
                    .unwrap()
                    .contains("default-src 'self'")
            );
            assert!(
                !to_bytes(response.into_body(), 1024 * 1024)
                    .await
                    .unwrap()
                    .is_empty()
            );
        }
        for (method, path, body, expected) in [
            (
                Method::GET,
                "/api/login",
                "".into(),
                StatusCode::METHOD_NOT_ALLOWED,
            ),
            (Method::GET, "/Cargo.toml", "".into(), StatusCode::NOT_FOUND),
            (
                Method::POST,
                "/api/no-route",
                "{}".into(),
                StatusCode::NOT_FOUND,
            ),
            (
                Method::POST,
                "/api/login",
                "x".repeat(BODY_LIMIT + 1),
                StatusCode::PAYLOAD_TOO_LARGE,
            ),
            (
                Method::GET,
                "//rebound.test/",
                "".into(),
                StatusCode::BAD_REQUEST,
            ),
            (
                Method::GET,
                "http://rebound.test/",
                "".into(),
                StatusCode::BAD_REQUEST,
            ),
        ] {
            assert_eq!(
                app.clone()
                    .oneshot(request(method, path, body))
                    .await
                    .unwrap()
                    .status(),
                expected,
                "{path}"
            );
        }
        let mut req = request(Method::POST, "/api/login", "{}");
        req.headers_mut().remove(header::CONTENT_TYPE);
        assert_eq!(
            app.clone().oneshot(req).await.unwrap().status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
        let mut req = request(Method::POST, "/api/login", "{}");
        req.headers_mut()
            .insert(header::ORIGIN, "https://untrusted.test".parse().unwrap());
        assert_eq!(
            app.clone().oneshot(req).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
        let mut req = request(Method::GET, "/", "");
        req.headers_mut()
            .insert(header::HOST, "rebound.test:3000".parse().unwrap());
        assert_eq!(
            app.clone().oneshot(req).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );

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
        let token = login["token"].as_str().unwrap();
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
        let mut tampered = token.as_bytes().to_vec();
        let signature = token.rfind('.').unwrap() + 1;
        tampered[signature] = if tampered[signature] == b'A' {
            b'B'
        } else {
            b'A'
        };
        assert_eq!(
            post(
                &app,
                "/api/validate",
                json!({"token":String::from_utf8(tampered).unwrap()}),
                StatusCode::OK
            )
            .await,
            json!({"valid":false})
        );
        assert_eq!(
            post(
                &app,
                "/api/validate",
                json!({"token":"not.a.token"}),
                StatusCode::OK
            )
            .await,
            json!({"valid":false})
        );
        for endpoint in ["signup", "login", "validate"] {
            let path = format!("/api/{endpoint}");
            post(&app, &path, json!({}), StatusCode::BAD_REQUEST).await;
            assert_eq!(
                app.clone()
                    .oneshot(request(Method::POST, &path, "{"))
                    .await
                    .unwrap()
                    .status(),
                StatusCode::BAD_REQUEST
            );
        }
        let concurrent =
            json!({"email":"concurrent@example.test", "password":"a-local-demo-password"})
                .to_string();
        let (first, second) = tokio::join!(
            app.clone()
                .oneshot(request(Method::POST, "/api/signup", concurrent.clone())),
            app.clone()
                .oneshot(request(Method::POST, "/api/signup", concurrent))
        );
        let mut statuses = [
            first.unwrap().status().as_u16(),
            second.unwrap().status().as_u16(),
        ];
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
        let _full = slots.acquire_many(8).await.unwrap();
        assert_eq!(
            app.oneshot(request(Method::POST, "/api/login", "{}"))
                .await
                .unwrap()
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
}
