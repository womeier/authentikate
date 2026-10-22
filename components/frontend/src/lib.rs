//! The HTTP front-end.
//!
//! The runtime hands us a parsed `incoming-request`; we decide the request's
//! fate, forward a byte body to `authentikate:service/api`, and write back the
//! status and body the Rocq service returned.  No JSON is parsed here, no
//! credential is inspected, and no key is held: `config` carries an opaque
//! Ed25519 handle, and signing happens inside the crypto component.
//!
//! What moved here from the host: the request target's form, the Host/Origin
//! policy, routing, the static assets, the method and media-type checks, the
//! body limit and read deadline, and the response security headers.  What
//! stayed in the host: the engine, fuel and memory limits, admission control,
//! and the `wasi:keyvalue` provider, which has to outlive a request because
//! each request gets a fresh instance.

wit_bindgen::generate!({ world: "frontend", path: "wit", generate_all });

mod policy;

use authentikate::crypto::{argon2, ed25519};
use authentikate::service::api;
use authentikate::frontend::settings;
use exports::wasi::http::incoming_handler::Guest;
use policy::{
    is_json, is_origin_form, route, Operation, Policy, Route, BODY_LIMIT, READ_DEADLINE_NS,
};
// `clocks0_2_4` rather than `clocks`: the vendored `service.wit` world imports
// `wasi:clocks/wall-clock@0.2.0` while `wasi:http/types` imports
// `wasi:clocks/monotonic-clock@0.2.4`, so two versions of the package are in
// the resolve and wit-bindgen disambiguates by version.  Both are byte-identical
// upstream copies; unifying them would mean editing the service's WIT and the
// import string in its hand-written adapter, which is not worth a nicer name.
use wasi::clocks0_2_4::monotonic_clock;
use wasi::http::types::{
    Fields, IncomingRequest, Method, OutgoingBody, OutgoingResponse, ResponseOutparam,
};
use wasi::io::{poll, streams::StreamError};

const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; \
                   connect-src 'self'; img-src 'self'; base-uri 'none'; \
                   frame-ancestors 'none'; form-action 'self'";
const JSON: &str = "application/json; charset=utf-8";

/// A fixed salt for the missing-account hash.  It is not a secret -- it exists
/// only so that a login for an unknown email runs the same Argon2 as one for a
/// known email with the wrong password.  Being constant costs nothing: the
/// result is discarded, because `login_check` in Api.v returns `Unauthorized`
/// whenever the lookup found nothing, whatever the hash said.
const DUMMY_SALT: [u8; 16] = *b"authentikate-abs";

struct Component;

struct Reply {
    status: u16,
    content_type: &'static str,
    body: Vec<u8>,
    allow_post: bool,
}

/// Fixed messages, so the body needs no JSON escaping; `errors_need_no_escaping`
/// holds that in place.
fn error(status: u16, message: &str) -> Reply {
    Reply {
        status,
        content_type: JSON,
        body: format!("{{\"error\":\"{message}\"}}").into_bytes(),
        allow_post: false,
    }
}

enum BodyError {
    TooLarge,
    TimedOut,
    Interrupted,
}

/// Drain the request body, counting bytes rather than trusting Content-Length,
/// so the limit binds on a chunked body too.  The deadline is polled alongside
/// the stream: a client that opens a body and stalls does not pin an instance.
fn read_body(request: &IncomingRequest) -> Result<Vec<u8>, BodyError> {
    let body = request.consume().map_err(|()| BodyError::Interrupted)?;
    let stream = body.stream().map_err(|()| BodyError::Interrupted)?;
    let deadline = monotonic_clock::subscribe_duration(READ_DEADLINE_NS);
    let ready = stream.subscribe();
    let mut buffer = Vec::new();
    loop {
        // Only the deadline being ready is the timeout; a stream that is also
        // ready gets read first.
        if !poll::poll(&[&ready, &deadline]).contains(&0) {
            return Err(BodyError::TimedOut);
        }
        match stream.read(4096) {
            Ok(chunk) => {
                buffer.extend_from_slice(&chunk);
                if buffer.len() > BODY_LIMIT {
                    return Err(BodyError::TooLarge);
                }
            }
            Err(StreamError::Closed) => return Ok(buffer),
            Err(StreamError::LastOperationFailed(_)) => return Err(BodyError::Interrupted),
        }
    }
}

/// Everything the host told us, with the origin policy already derived.
struct Settings {
    config: settings::Config,
    policy: Policy,
}

impl Settings {
    fn load() -> Self {
        let config = settings::get();
        Self {
            policy: Policy {
                approved_origin: config.approved_origin.clone(),
                approved_authorities: config.approved_authorities.clone(),
            },
            config,
        }
    }

    /// Assemble the service configuration.  The Ed25519 and Argon2 instances
    /// here are the ones WAC wires into the service, so `key` names a key in
    /// the service's own view and `dummy_params` are the parameters real
    /// records are enrolled under -- which is what keeps the missing-account
    /// path indistinguishable by duration.
    fn service_config(&self) -> Option<api::Config> {
        let key = ed25519::import_key(&self.config.signing_seed).ok()?;
        let params = argon2::recommended_params();
        Some(api::Config {
            key,
            pubkey: ed25519::public_key(key).ok()?,
            iss: self.config.issuer.clone().into_bytes(),
            ttl: self.config.ttl,
            dummy_salt: DUMMY_SALT.to_vec(),
            dummy_tag: vec![0; params.tag_length as usize],
            dummy_params: api::Argon2Params {
                // 2 is argon2id, the algorithm `enroll` writes into a record.
                algorithm: 2,
                memory_kib: params.memory_kib,
                iterations: params.iterations,
                parallelism: params.parallelism,
                tag_length: params.tag_length,
            },
            email_from: self.config.email_from.clone().into_bytes(),
        })
    }
}

fn respond(request: &IncomingRequest) -> Reply {
    let settings = Settings::load();
    let Some(target) = request.path_with_query() else {
        return error(400, "Use an origin-form relative request target");
    };
    if !is_origin_form(&target) {
        return error(400, "Use an origin-form relative request target");
    }
    let headers = request.headers();
    let field = |name: &str| {
        headers
            .get(&name.to_string())
            .into_iter()
            .map(|value| String::from_utf8_lossy(&value).into_owned())
            .collect::<Vec<_>>()
    };
    if !settings
        .policy
        .permits(request.authority().as_deref(), &field("origin"))
    {
        return error(403, "Host or Origin is not allowed");
    }
    let operation = match route(&target) {
        Route::Asset { kind, body } => {
            return match request.method() {
                Method::Get => Reply {
                    status: 200,
                    content_type: kind,
                    body: body.as_bytes().to_vec(),
                    allow_post: false,
                },
                Method::Head => Reply {
                    status: 200,
                    content_type: kind,
                    body: Vec::new(),
                    allow_post: false,
                },
                _ => error(404, "Not found"),
            };
        }
        Route::NotFound => return error(404, "Not found"),
        Route::Api(operation) => operation,
    };
    if !matches!(request.method(), Method::Post) {
        return Reply {
            allow_post: true,
            ..error(405, "Use POST")
        };
    }
    if !is_json(field("content-type").first().map(String::as_str)) {
        return error(415, "Use application/json");
    }
    // An honest Content-Length is refused before the body is read; a dishonest
    // one is caught by the counting in `read_body`.
    if field("content-length")
        .first()
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|length| length > BODY_LIMIT as u64)
    {
        return error(413, "Request body exceeds 16 KiB");
    }
    let body = match read_body(request) {
        Ok(body) => body,
        Err(BodyError::TooLarge) => return error(413, "Request body exceeds 16 KiB"),
        Err(BodyError::TimedOut) => return error(408, "Request body timed out"),
        Err(BodyError::Interrupted) => return error(400, "Request interrupted"),
    };
    let Some(config) = settings.service_config() else {
        return error(500, "Service is misconfigured");
    };
    let response = match operation {
        Operation::Signup => api::signup(&config, &body),
        Operation::Login => api::login(&config, &body),
        Operation::Validate => api::validate(&config, &body),
    };
    Reply {
        // The service's statuses are the seven in Api.v's `status`; anything
        // else would be a broken artifact, not a request to answer.
        status: u16::try_from(response.status).unwrap_or(500),
        content_type: JSON,
        body: response.body,
        allow_post: false,
    }
}

fn send(outparam: ResponseOutparam, reply: Reply) {
    let headers = Fields::new();
    let set = |name: &str, value: &str| {
        // A rejected header name would be a bug here, not input-dependent.
        let _ = headers.append(&name.to_string(), &value.as_bytes().to_vec());
    };
    set("content-type", reply.content_type);
    set("cache-control", "no-store");
    set("x-content-type-options", "nosniff");
    set("referrer-policy", "no-referrer");
    set("content-security-policy", CSP);
    if reply.allow_post {
        set("allow", "POST");
    }
    let response = OutgoingResponse::new(headers);
    let _ = response.set_status_code(reply.status);
    let Ok(body) = response.body() else {
        return ResponseOutparam::set(outparam, Err(wasi::http::types::ErrorCode::InternalError(None)));
    };
    ResponseOutparam::set(outparam, Ok(response));
    {
        let Ok(stream) = body.write() else { return };
        // WASI blocking-write-and-flush accepts at most 4096 bytes per call.
        for chunk in reply.body.chunks(4096) {
            if stream.blocking_write_and_flush(chunk).is_err() {
                break;
            }
        }
    }
    let _ = OutgoingBody::finish(body, None);
}

impl Guest for Component {
    fn handle(request: IncomingRequest, response_out: ResponseOutparam) {
        send(response_out, respond(&request));
    }
}

export!(Component);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_need_no_escaping() {
        for message in [
            "Use an origin-form relative request target",
            "Host or Origin is not allowed",
            "Not found",
            "Use POST",
            "Use application/json",
            "Request body exceeds 16 KiB",
            "Request body timed out",
            "Request interrupted",
            "Service is misconfigured",
        ] {
            assert!(
                !message.contains(['"', '\\']) && !message.contains(|c: char| c.is_control()),
                "{message}"
            );
            let reply = error(400, message);
            assert_eq!(
                String::from_utf8(reply.body).unwrap(),
                format!("{{\"error\":\"{message}\"}}")
            );
        }
    }

    #[test]
    fn dummy_salt_meets_the_argon2_minimum() {
        assert!(DUMMY_SALT.len() >= 8);
    }
}
