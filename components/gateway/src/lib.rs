//! The HTTP gateway.
//!
//! The runtime hands us a parsed `incoming-request`; we decide the request's
//! fate, forward a byte body to `authentikate:service/api`, and write back the
//! status and body the Rocq service returned.  No JSON is parsed here and no
//! credential is inspected.  Nor is any key held, and that is now structural
//! rather than a promise: the signing seed lives in
//! `authentikate:config/service`, which only the service's world imports, so
//! there is no import here through which it could arrive.
//!
//! What moved here from the host: the request target's form, the Host/Origin
//! policy, routing, the static assets, the method and media-type checks, the
//! body limit and read deadline, and the response security headers.  What
//! stayed in the host: the engine, fuel and memory limits, admission control,
//! and the storage directory preopen. The separate storage component preserves
//! accounts on disk across fresh per-request instances.

wit_bindgen::generate!({ world: "gateway", path: "wit", generate_all });

mod policy;

use authentikate::config;
use authentikate::service::api;
use exports::wasi::http::incoming_handler::Guest;
use policy::{
    is_json, is_origin_form, route, Operation, Policy, Route, BODY_LIMIT, READ_DEADLINE_NS,
};
use wasi::clocks::monotonic_clock;
use wasi::http::types::{
    Fields, IncomingRequest, Method, OutgoingBody, OutgoingResponse, ResponseOutparam,
};
use wasi::io::{poll, streams::StreamError};

const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; \
                   connect-src 'self'; img-src 'self'; base-uri 'none'; \
                   frame-ancestors 'none'; form-action 'self'";
const JSON: &str = "application/json; charset=utf-8";

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

fn respond(request: &IncomingRequest) -> Reply {
    let rules = config::policy::get();
    let allowed = Policy {
        approved_origin: rules.approved_origin,
        approved_authorities: rules.approved_authorities,
    };
    let Some(target) = request.path_with_query() else {
        return error(400, "Use an origin-form relative request target");
    };
    if !is_origin_form(&target) {
        return error(400, "Use an origin-form relative request target");
    }
    let headers = request.headers();
    let field = |name: &str| {
        headers
            .get(name)
            .into_iter()
            .map(|value| String::from_utf8_lossy(&value).into_owned())
            .collect::<Vec<_>>()
    };
    if !allowed.permits(request.authority().as_deref(), &field("origin")) {
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
    // No configuration crosses this call.  The service's adapter reads the
    // seed, the issuer, the TTL, the sender and the dummy Argon2 cost
    // parameters for itself, so a 500 for a bad seed is now its answer to
    // give, not ours to anticipate.
    let response = match operation {
        Operation::Signup => api::signup(&body),
        Operation::Login => api::login(&body),
        Operation::Validate => api::validate(&body),
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
        let _ = headers.append(name, value.as_bytes());
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
        return ResponseOutparam::set(
            outparam,
            Err(wasi::http::types::ErrorCode::InternalError(None)),
        );
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
}
