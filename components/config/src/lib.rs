//! Fail-closed, provisioned configuration. Parsing is also testable without WASI.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use url::{Host, Url};
use zeroize::Zeroizing;

pub const MAX_CONFIG_BYTES: usize = 64 * 1024;
pub const MAX_KEY_BYTES: usize = 45;

// Errors deliberately contain no input, JSON diagnostics, or key material.
#[derive(Debug, PartialEq, Eq)]
pub struct InvalidConfig;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub service: Service,
    pub policy: Policy,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Service {
    pub issuer: String,
    pub token_ttl_seconds: u64,
    pub email_from: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub approved_origin: Option<String>,
    pub approved_authorities: Vec<String>,
}

fn domain(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.starts_with(|c: char| c.is_ascii_alphanumeric())
                && label.ends_with(|c: char| c.is_ascii_alphanumeric())
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

fn origin(value: &str) -> Result<String, InvalidConfig> {
    if value.bytes().any(|b| b <= 32 || b == 127 || b == b'\\') {
        return Err(InvalidConfig);
    }
    let (scheme, rest) = value.split_once("://").ok_or(InvalidConfig)?;
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return Err(InvalidConfig);
    }
    let authority = rest.strip_suffix('/').unwrap_or(rest);
    if authority.is_empty() || authority.ends_with(':') || authority.contains(['/', '?', '#', '@'])
    {
        return Err(InvalidConfig);
    }
    let parsed = Url::parse(value).map_err(|_| InvalidConfig)?;
    if !matches!(parsed.scheme(), "http" | "https")
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.port() == Some(0)
    {
        return Err(InvalidConfig);
    }
    match parsed.host() {
        Some(Host::Domain(name)) if domain(name) => (),
        Some(Host::Ipv4(_) | Host::Ipv6(_)) => (),
        _ => return Err(InvalidConfig),
    }
    Ok(parsed.origin().ascii_serialization())
}

fn sender(value: &str) -> bool {
    if value.len() > 320 || !value.bytes().all(|b| (32..=126).contains(&b)) {
        return false;
    }
    let mailbox = if let Some((name, address)) = value.split_once(" <") {
        if name.trim().is_empty() || name.contains(['<', '>', '"', '\\']) {
            return false;
        }
        let Some(address) = address.strip_suffix('>') else {
            return false;
        };
        address
    } else {
        value
    };
    let Some((local, host)) = mailbox.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && local.len() <= 64
        && !local.starts_with('.')
        && !local.ends_with('.')
        && !local.contains("..")
        && local
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".!#$%&'*+-/=?^_`{|}~".contains(&b))
        && domain(host)
}

pub fn parse(bytes: &[u8]) -> Result<Config, InvalidConfig> {
    if bytes.len() > MAX_CONFIG_BYTES {
        return Err(InvalidConfig);
    }
    let mut config: Config = serde_json::from_slice(bytes).map_err(|_| InvalidConfig)?;
    let service = &config.service;
    if service.issuer.trim().is_empty()
        || !service
            .issuer
            .bytes()
            .all(|b| (32..=126).contains(&b) && b != b'"' && b != b'\\')
        || service.token_ttl_seconds == 0
        || !sender(&service.email_from)
    {
        return Err(InvalidConfig);
    }
    if let Some(value) = &mut config.policy.approved_origin {
        *value = origin(value)?;
    }
    if config.policy.approved_origin.is_none() && config.policy.approved_authorities.is_empty() {
        return Err(InvalidConfig);
    }
    for authority in &mut config.policy.approved_authorities {
        // Authorities have no scheme or trailing slash; HTTP matches gateway fallback policy.
        if authority.contains(['/', '?', '#', '@']) {
            return Err(InvalidConfig);
        }
        *authority = origin(&format!("http://{authority}"))?
            .strip_prefix("http://")
            .ok_or(InvalidConfig)?
            .to_owned();
    }
    config.policy.approved_authorities.sort_unstable();
    config.policy.approved_authorities.dedup();
    Ok(config)
}

pub fn parse_key(bytes: &[u8]) -> Result<[u8; 32], InvalidConfig> {
    if bytes.len() > MAX_KEY_BYTES {
        return Err(InvalidConfig);
    }
    let bytes = bytes
        .strip_suffix(b"\r\n")
        .or_else(|| bytes.strip_suffix(b"\n"))
        .unwrap_or(bytes);
    let mut decoded = Zeroizing::new(Vec::new());
    URL_SAFE_NO_PAD
        .decode_vec(bytes, &mut decoded)
        .map_err(|_| InvalidConfig)?;
    decoded.as_slice().try_into().map_err(|_| InvalidConfig)
}

#[cfg(target_arch = "wasm32")]
mod component {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

    use super::*;
    use exports::authentikate::config::{policy, service};
    use wasi::filesystem::types::{
        Descriptor, DescriptorFlags, DescriptorType, OpenFlags, PathFlags,
    };

    struct Component;

    fn directory() -> Result<Descriptor, InvalidConfig> {
        wasi::filesystem::preopens::get_directories()
            .into_iter()
            .find_map(|(fd, name)| (name == "/config").then_some(fd))
            .ok_or(InvalidConfig)
    }

    fn read(
        dir: &Descriptor,
        name: &str,
        limit: usize,
    ) -> Result<Zeroizing<Vec<u8>>, InvalidConfig> {
        let file = dir
            .open_at(
                PathFlags::empty(),
                name,
                OpenFlags::empty(),
                DescriptorFlags::READ,
            )
            .map_err(|_| InvalidConfig)?;
        if file.get_type().map_err(|_| InvalidConfig)? != DescriptorType::RegularFile {
            return Err(InvalidConfig);
        }
        // Avoid reallocating partially read secret bytes into an unwiped allocation.
        let mut bytes = Zeroizing::new(Vec::with_capacity(limit + 1));
        loop {
            // The extra byte distinguishes a full valid file from a truncated oversized file.
            let count = (limit + 1 - bytes.len()).min(4096);
            let (chunk, eof) = file
                .read(count as u64, bytes.len() as u64)
                .map_err(|_| InvalidConfig)?;
            let chunk = Zeroizing::new(chunk);
            if bytes.len() + chunk.len() > limit || (chunk.is_empty() && !eof) {
                return Err(InvalidConfig);
            }
            bytes.extend_from_slice(&chunk);
            if eof {
                return Ok(bytes);
            }
        }
    }

    fn load(dir: &Descriptor) -> Result<Config, InvalidConfig> {
        parse(&read(dir, "config.json", MAX_CONFIG_BYTES)?)
    }

    impl service::Guest for Component {
        fn get() -> service::Settings {
            let result = (|| {
                let dir = directory()?;
                let config = load(&dir)?;
                let key = Zeroizing::new(parse_key(&read(&dir, "signing.key", MAX_KEY_BYTES)?)?);
                Ok::<_, InvalidConfig>(service::Settings {
                    signing_key: key.to_vec(),
                    iss: config.service.issuer,
                    ttl: config.service.token_ttl_seconds,
                    email_from: config.service.email_from,
                })
            })();
            result.unwrap_or_else(|_| panic!("configuration unavailable or invalid"))
        }
    }

    impl policy::Guest for Component {
        fn get() -> policy::Rules {
            let result = directory().and_then(|dir| load(&dir));
            let config = result.unwrap_or_else(|_| panic!("configuration unavailable or invalid"));
            policy::Rules {
                approved_origin: config.policy.approved_origin,
                approved_authorities: config.policy.approved_authorities,
            }
        }
    }

    export!(Component);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn example() -> Value {
        json!({
            "service": {
                "issuer": "authentikate",
                "token_ttl_seconds": 600,
                "email_from": "Authentikate <hello@example.test>"
            },
            "policy": {
                "approved_authorities": ["LOCALHOST:3000", "[::1]:3000", "127.0.0.1:3000"]
            }
        })
    }

    fn valid(value: &Value) -> bool {
        parse(&serde_json::to_vec(value).unwrap()).is_ok()
    }

    #[test]
    fn normalizes_policy_and_preserves_service() {
        let mut value = example();
        value["policy"]["approved_origin"] = json!("HTTPS://Demo.Example.Test:443/");
        value["policy"]["approved_authorities"] =
            json!(["LOCALHOST:80", "localhost", "[::1]:3000"]);
        let config = parse(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(
            config.policy.approved_origin.as_deref(),
            Some("https://demo.example.test")
        );
        assert_eq!(
            config.policy.approved_authorities,
            ["[::1]:3000", "localhost"]
        );
        assert_eq!(config.service.issuer, "authentikate");
        assert_eq!(config.service.token_ttl_seconds, 600);
        assert_eq!(
            config.service.email_from,
            "Authentikate <hello@example.test>"
        );
    }

    #[test]
    fn denies_unknown_duplicate_missing_and_wrongly_typed_fields() {
        for pointer in ["", "/service", "/policy"] {
            let mut value = example();
            value.pointer_mut(pointer).unwrap()["typo"] = json!(true);
            assert!(!valid(&value), "{pointer}");
        }
        for (object, field) in [
            ("", "service"),
            ("", "policy"),
            ("service", "issuer"),
            ("service", "token_ttl_seconds"),
            ("service", "email_from"),
            ("policy", "approved_authorities"),
        ] {
            let mut value = example();
            let target = if object.is_empty() {
                &mut value
            } else {
                &mut value[object]
            };
            target.as_object_mut().unwrap().remove(field);
            assert!(!valid(&value), "{object}.{field}");
        }
        for ttl in [json!(0), json!(-1), json!(1.5), json!("600"), Value::Null] {
            let mut value = example();
            value["service"]["token_ttl_seconds"] = ttl;
            assert!(!valid(&value));
        }
        let encoded = example()
            .to_string()
            .replace("\"issuer\":", "\"issuer\":\"duplicate\",\"issuer\":");
        assert!(parse(encoded.as_bytes()).is_err());
        assert!(parse(b"{} {}").is_err());
        assert!(parse(b"\xff").is_err());
    }

    #[test]
    fn rejects_unsafe_issuers_and_senders() {
        for issuer in [
            "",
            "  ",
            "quote\"",
            "back\\slash",
            "line\nfeed",
            "\u{7f}",
            "caf\u{e9}",
        ] {
            let mut value = example();
            value["service"]["issuer"] = json!(issuer);
            assert!(!valid(&value), "{issuer:?}");
        }
        for from in [
            "",
            "hello",
            "a@@example.test",
            "a@-bad.test",
            ".a@example.test",
            "a..b@example.test",
            "a@example.test\r\nBcc: x@y.test",
            "Name <a@example.test> trailing",
            "<a@example.test>",
            "a@exam_ple.test",
            "Name <a@example.test",
            "a@example.test ",
        ] {
            let mut value = example();
            value["service"]["email_from"] = json!(from);
            assert!(!valid(&value), "{from:?}");
        }
        assert!(sender("hello+signup@example.test"));
    }

    #[test]
    fn rejects_ambiguous_or_non_origin_urls() {
        for value in [
            "",
            "null",
            "ftp://example.test",
            "https:example.test",
            "https:///example.test",
            " https://example.test",
            "https://example.test\n",
            "https://example.test/a",
            "https://example.test/a/..",
            "https://example.test//",
            "https://example.test?x",
            "https://example.test#",
            "https://user@example.test",
            "https://@example.test",
            "https://user:pass@example.test",
            "https://example.test\\evil",
            "https://*.example.test",
            "https://example.test:0",
            "https://example.test:",
            "https://example.test:65536",
            "https://bad_host.test",
            "https://-bad.test",
        ] {
            assert!(origin(value).is_err(), "{value:?}");
        }
        assert_eq!(origin("http://[::1]:3000/").unwrap(), "http://[::1]:3000");
        assert_eq!(origin("http://127.0.0.1:80").unwrap(), "http://127.0.0.1");
    }

    #[test]
    fn requires_nonempty_safe_policy_even_with_approved_origin() {
        let mut value = example();
        value["policy"]["approved_authorities"] = json!([]);
        assert!(!valid(&value));
        value["policy"]["approved_origin"] = json!("https://example.test");
        assert!(valid(&value));
        for authority in [
            "",
            "*",
            "localhost/",
            "https://example.test",
            "a@b.test",
            "a?b",
            "a#b",
            " localhost",
            "localhost:0",
            "localhost:",
            "[::1",
            "localhost\r\n",
        ] {
            value["policy"]["approved_authorities"] = json!([authority]);
            assert!(!valid(&value), "{authority:?}");
        }
    }

    #[test]
    fn enforces_json_byte_bound_including_trailing_whitespace() {
        let mut bytes = example().to_string().into_bytes();
        bytes.resize(MAX_CONFIG_BYTES, b' ');
        assert!(parse(&bytes).is_ok());
        bytes.push(b' ');
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn signing_key_is_base64url_of_exactly_32_bytes() {
        let bytes: Vec<u8> = (0..32).collect();
        let encoded = URL_SAFE_NO_PAD.encode(&bytes);
        for suffix in ["", "\n", "\r\n"] {
            assert_eq!(
                parse_key(format!("{encoded}{suffix}").as_bytes())
                    .unwrap()
                    .as_slice(),
                bytes
            );
        }
        for size in [0, 1, 31, 33, 64, 1024] {
            assert_eq!(
                parse_key(URL_SAFE_NO_PAD.encode(vec![42; size]).as_bytes()),
                Err(InvalidConfig)
            );
        }
        assert_eq!(parse_key(&bytes), Err(InvalidConfig));
        assert_eq!(parse_key(&[0; 32]), Err(InvalidConfig));
        for invalid in [
            format!("{encoded}="),
            encoded[..encoded.len() - 1].to_owned(),
            base64::engine::general_purpose::STANDARD_NO_PAD.encode([255; 32]),
            encoded.replace('A', "!"),
            format!(" {encoded}"),
            format!("{encoded}\n\n"),
            format!("{encoded}\r"),
        ] {
            assert_eq!(parse_key(invalid.as_bytes()), Err(InvalidConfig));
        }
        assert_eq!(
            parse_key(URL_SAFE_NO_PAD.encode([255; 32]).as_bytes()),
            Ok([255; 32])
        );
        assert_eq!(
            parse_key(URL_SAFE_NO_PAD.encode([251; 32]).as_bytes()),
            Ok([251; 32])
        );
        assert_eq!(format!("{InvalidConfig:?}"), "InvalidConfig");
    }
}
