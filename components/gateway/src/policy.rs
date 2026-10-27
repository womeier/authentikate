//! The decisions, as pure functions.
//!
//! Everything in this module is reachable from a native `cargo test`: it
//! borrows strings and returns verdicts, and touches no WASI import.  That is
//! the point of the split -- the checks that used to sit in the host's request
//! path are security-relevant, so they should be testable without a component,
//! an engine or a socket.
//!
//! None of it is *proved*.  Routing and the Host/Origin policy moved from the
//! host into a component here; they did not move into Rocq.  See README's
//! Trusted Computing Base section.

/// Matches the host's old limit, and applies to chunked bodies too because
/// this layer counts the bytes it reads rather than trusting Content-Length.
pub const BODY_LIMIT: usize = 16 * 1024;

/// Fixed 15-second budget for draining the request body, enforced against the
/// monotonic clock rather than wall time.
pub const READ_DEADLINE_NS: u64 = 15_000_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Signup,
    Login,
    Validate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    Api(Operation),
    Asset {
        kind: &'static str,
        body: &'static str,
    },
    NotFound,
}

/// Embedded at build time, as they were in the host.  Serving them from the
/// component is what lets the composed artifact answer every route it claims.
const INDEX: &str = include_str!("../assets/index.html");
const STYLE: &str = include_str!("../assets/style.css");
const SCRIPT: &str = include_str!("../assets/app.js");

/// A request target must be in origin-form: `/path` with an optional query.
///
/// Absolute-form (`http://elsewhere/`) and a protocol-relative target
/// (`//elsewhere/`) are both rejected, because both invite a reader -- or a
/// proxy -- to disagree with us about which authority the request names.
pub fn is_origin_form(target: &str, has_scheme: bool) -> bool {
    !has_scheme && target.starts_with('/') && !target.starts_with("//")
}

/// Route on the path alone; a query string selects nothing here.
pub fn route(target: &str) -> Route {
    match target.split(['?', '#']).next().unwrap_or("") {
        "/api/signup" => Route::Api(Operation::Signup),
        "/api/login" => Route::Api(Operation::Login),
        "/api/validate" => Route::Api(Operation::Validate),
        "/" => Route::Asset {
            kind: "text/html; charset=utf-8",
            body: INDEX,
        },
        "/style.css" => Route::Asset {
            kind: "text/css; charset=utf-8",
            body: STYLE,
        },
        "/app.js" => Route::Asset {
            kind: "text/javascript; charset=utf-8",
            body: SCRIPT,
        },
        _ => Route::NotFound,
    }
}

/// `application/json`, with or without parameters.
pub fn is_json(content_type: Option<&str>) -> bool {
    content_type.is_some_and(|value| {
        value
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .eq_ignore_ascii_case("application/json")
    })
}

/// Which authority and `Origin` a request may carry.
///
/// Two modes, matching the host's previous behaviour exactly.  With an
/// approved origin configured, the authority must be that origin's authority.
/// Without one, the authority must be one the host is actually listening on --
/// the host supplies that list, because the bound port is host knowledge
/// (`LISTEN=127.0.0.1:0` picks one at runtime), while the rule applied to it
/// is this component's.
pub struct Policy {
    /// Already validated and normalized by the host (scheme + lowercased
    /// authority, no credentials, path, query or fragment), so the comparison
    /// below is a comparison and not a second parse.
    pub approved_origin: Option<String>,
    pub approved_authorities: Vec<String>,
}

impl Policy {
    pub fn permits(&self, authority: Option<&str>, origins: &[String]) -> bool {
        let Some(authority) = authority else {
            return false;
        };
        let expected = match &self.approved_origin {
            Some(origin) => {
                let want = origin.split_once("://").map_or("", |(_, rest)| rest);
                if !authority.eq_ignore_ascii_case(want) {
                    return false;
                }
                origin.clone()
            }
            None => {
                if !self
                    .approved_authorities
                    .iter()
                    .any(|allowed| authority.eq_ignore_ascii_case(allowed))
                {
                    return false;
                }
                format!("http://{}", authority.to_ascii_lowercase())
            }
        };
        // A missing Origin is allowed, for non-browser clients.  More than one
        // is never allowed: picking among them is how a filter gets bypassed.
        origins.is_empty() || (origins.len() == 1 && origins[0] == expected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loopback() -> Policy {
        Policy {
            approved_origin: None,
            approved_authorities: ["127.0.0.1:3000", "localhost:3000", "[::1]:3000"]
                .map(String::from)
                .to_vec(),
        }
    }

    #[test]
    fn origin_form_only() {
        for target in ["/", "/api/login", "/style.css?v=2"] {
            assert!(is_origin_form(target, false), "{target}");
            // P3 exposes an absolute URI's path separately from its scheme.
            assert!(!is_origin_form(target, true), "{target}");
        }
        for target in ["//rebound.test/", "http://rebound.test/", "", "rebound"] {
            assert!(!is_origin_form(target, false), "{target}");
        }
    }

    #[test]
    fn routes_ignore_the_query() {
        assert_eq!(route("/api/login"), Route::Api(Operation::Login));
        assert_eq!(route("/api/signup"), Route::Api(Operation::Signup));
        assert_eq!(route("/api/validate"), Route::Api(Operation::Validate));
        assert_eq!(route("/api/login?x=1"), Route::Api(Operation::Login));
        assert!(matches!(route("/"), Route::Asset { .. }));
        assert!(matches!(route("/style.css?v=2"), Route::Asset { .. }));
        assert_eq!(route("/Cargo.toml"), Route::NotFound);
        assert_eq!(route("/api/no-route"), Route::NotFound);
    }

    #[test]
    fn assets_are_non_empty() {
        for target in ["/", "/style.css", "/app.js"] {
            let Route::Asset { body, .. } = route(target) else {
                panic!("{target} is not an asset");
            };
            assert!(!body.is_empty(), "{target}");
        }
    }

    #[test]
    fn media_type_accepts_parameters() {
        assert!(is_json(Some("application/json")));
        assert!(is_json(Some("application/json; charset=utf-8")));
        assert!(is_json(Some("APPLICATION/JSON")));
        assert!(!is_json(None));
        assert!(!is_json(Some("text/plain")));
        assert!(!is_json(Some("application/jsonx")));
    }

    // Mirrors the host's former `host_and_origin_policy` test.
    #[test]
    fn host_and_origin_policy() {
        let policy = loopback();
        for (authority, origin, expected) in [
            ("127.0.0.1:3000", None, true),
            ("localhost:3000", Some("http://localhost:3000"), true),
            ("[::1]:3000", Some("http://[::1]:3000"), true),
            ("rebound.test:3000", Some("http://rebound.test:3000"), false),
            ("127.0.0.1:1", None, false),
            ("127.0.0.1:3000", Some("https://untrusted.test"), false),
            ("127.0.0.1:3000", Some("null"), false),
        ] {
            let origins = origin.map(String::from).into_iter().collect::<Vec<_>>();
            assert_eq!(
                policy.permits(Some(authority), &origins),
                expected,
                "{authority} {origin:?}"
            );
        }
        // A request with no authority at all is refused, not defaulted.
        assert!(!policy.permits(None, &[]));

        let policy = Policy {
            approved_origin: Some("https://demo.example.test".into()),
            approved_authorities: vec![],
        };
        assert!(!policy.permits(Some("127.0.0.1:3000"), &[]));
        assert!(policy.permits(Some("demo.example.test"), &[]));
        assert!(policy.permits(
            Some("demo.example.test"),
            &["https://demo.example.test".into()]
        ));
        // Two Origin headers, even two agreeing ones.
        assert!(!policy.permits(
            Some("demo.example.test"),
            &[
                "https://demo.example.test".into(),
                "https://demo.example.test".into()
            ]
        ));
    }
}
