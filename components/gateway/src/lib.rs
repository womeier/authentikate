//! The HTTP gateway.
//!
//! The runtime hands us a parsed `request`; we decide the request's
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

// Honor WIT async annotations, leaving the service/config imports synchronous.
wit_bindgen::generate!({ world: "gateway", path: "wit", generate_all });

mod policy;

use authentikate::config;
use authentikate::service::api;
use exports::wasi::http::handler::Guest;
use futures::future::{select, Either};
use policy::{
    is_json, is_origin_form, route, Operation, Policy, Route, BODY_LIMIT, READ_DEADLINE_NS,
};
use wasi::clocks::monotonic_clock;
use wasi::http::types::{ErrorCode, Fields, Method, Request, Response};
use wit_bindgen::StreamResult;

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
async fn read_body(request: Request) -> Result<Vec<u8>, BodyError> {
    let (result_tx, result_rx) = wit_future::new(|| Ok(()));
    let (mut stream, trailers) = Request::consume_body(request, result_rx);
    // Keep the result writer alive until reading ends. Its default acknowledges
    // consumption even on early rejection; the HTTP error is our response.
    let _result_tx = result_tx;
    let deadline = monotonic_clock::now().saturating_add(READ_DEADLINE_NS);
    let read = async move {
        let mut buffer = Vec::with_capacity(BODY_LIMIT + 1);
        loop {
            // Check time even when every read is immediately ready.
            if monotonic_clock::now() >= deadline {
                return Err(BodyError::TimedOut);
            }
            let (status, bytes) = stream.read(buffer).await;
            buffer = bytes;
            // read appends into spare capacity. Refuse the sentinel byte before
            // another read, so even a full buffer never causes a zero-byte read.
            if buffer.len() > BODY_LIMIT {
                return Err(BodyError::TooLarge);
            }
            match status {
                StreamResult::Complete(_) => {}
                StreamResult::Dropped => break,
                StreamResult::Cancelled => return Err(BodyError::Interrupted),
            }
        }
        // EOF alone is not success: p3 carries transport errors in trailers.
        trailers.await.map_err(|_| BodyError::Interrupted)?;
        Ok(buffer)
    };
    match select(
        std::pin::pin!(read),
        std::pin::pin!(monotonic_clock::wait_until(deadline)),
    )
    .await
    {
        Either::Left((result, _)) => result,
        Either::Right(_) => Err(BodyError::TimedOut),
    }
}

async fn respond(request: Request) -> Reply {
    let rules = config::policy::get();
    let allowed = Policy {
        approved_origin: rules.approved_origin,
        approved_authorities: rules.approved_authorities,
    };
    let Some(target) = request.get_path_with_query() else {
        return error(400, "Use an origin-form relative request target");
    };
    // P3 splits absolute URIs into scheme/authority/path; the path alone can
    // look like origin-form even when the original target was absolute-form.
    if !is_origin_form(&target, request.get_scheme().is_some()) {
        return error(400, "Use an origin-form relative request target");
    }
    let headers = request.get_headers();
    let field = |name: &str| {
        headers
            .get(name)
            .into_iter()
            .map(|value| String::from_utf8_lossy(&value).into_owned())
            .collect::<Vec<_>>()
    };
    if !allowed.permits(request.get_authority().as_deref(), &field("origin")) {
        return error(403, "Host or Origin is not allowed");
    }
    let operation = match route(&target) {
        Route::Asset { kind, body } => {
            return match request.get_method() {
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
    if !matches!(request.get_method(), Method::Post) {
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
    let body = match read_body(request).await {
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

fn send(reply: Reply) -> Result<Response, ErrorCode> {
    let headers = Fields::new();
    let set = |name: &str, value: &str| {
        headers
            .append(name, value.as_bytes())
            .map_err(|_| ErrorCode::InternalError(None))
    };
    set("content-type", reply.content_type)?;
    set("cache-control", "no-store")?;
    set("x-content-type-options", "nosniff")?;
    set("referrer-policy", "no-referrer")?;
    set("content-security-policy", CSP)?;
    if reply.allow_post {
        set("allow", "POST")?;
    }
    let (mut body_tx, body_rx) = wit_stream::new();
    let (trailers_tx, trailers_rx) = wit_future::new(|| Ok(None));
    let (response, transmission) = Response::new(headers, Some(body_rx), trailers_rx);
    response
        .set_status_code(reply.status)
        .map_err(|_| ErrorCode::InternalError(None))?;
    // The reader is driven only after handle returns the response. Do not await
    // these writes in handle, or backpressure would deadlock the response.
    wit_bindgen::spawn(async move {
        let _unsent = body_tx.write_all(reply.body).await;
        drop(body_tx);
        drop(trailers_tx);
        let _ = transmission.await;
    });
    Ok(response)
}

impl Guest for Component {
    async fn handle(request: Request) -> Result<Response, ErrorCode> {
        send(respond(request).await)
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
