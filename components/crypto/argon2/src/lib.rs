//! Argon2, as a WebAssembly component.
//!
//! Derivation and verification are deterministic. Enrollment imports WASI
//! secure randomness to create a salt and returns a public JSON record.
//!
//! See `../wit/argon2.wit` for the interface and why it is shaped this way.

// std, not no_std: on wasm32-unknown-unknown the standard library's I/O is
// stubbed out and imports nothing, so using it costs no imports and saves
// hand-rolling a panic handler and a global allocator.
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

wit_bindgen::generate!({
    world: "password-hashing",
    path: "../wit",
    with: {
        "wasi:random/random@0.2.0": generate,
    },
});

use exports::authentikate::crypto::argon2::{
    Algorithm as WitAlgorithm, Error, Guest, Params as WitParams,
};

struct Component;

/// Argon2 accepts a password of up to 2^32 - 1 bytes, but a password that
/// large is an attack rather than a login; the limit here is generous and
/// finite.  Keeping it means `derive` cannot be used to make the host chew
/// through an arbitrary amount of input.
const MAX_PASSWORD: usize = 4096;

impl From<WitAlgorithm> for Algorithm {
    fn from(a: WitAlgorithm) -> Self {
        match a {
            WitAlgorithm::Argon2d => Algorithm::Argon2d,
            WitAlgorithm::Argon2i => Algorithm::Argon2i,
            WitAlgorithm::Argon2id => Algorithm::Argon2id,
        }
    }
}

/// OWASP's current recommendation for Argon2id: 19 MiB, two passes, one lane,
/// a 32-byte tag.
const RECOMMENDED: WitParams = WitParams {
    memory_kib: 19 * 1024,
    iterations: 2,
    parallelism: 1,
    tag_length: 32,
};

fn enrollment_with_salt(password: &[u8], salt: Vec<u8>) -> Result<Vec<u8>, Error> {
    let salt = Zeroizing::new(salt);
    if salt.len() != 16 {
        return Err(Error::InvalidParams(
            "enrollment entropy must contain exactly 16 bytes".into(),
        ));
    }
    let tag = Zeroizing::new(derive_into(
        password,
        &salt,
        WitAlgorithm::Argon2id,
        &RECOMMENDED,
    )?);
    // Only base64url strings and numbers are interpolated, so no JSON escaping
    // is needed. The resulting record is public, unlike the input password.
    Ok(format!(
        "{{\"salt\":\"{}\",\"tag\":\"{}\",\"algorithm\":2,\"memory_kib\":{},\"iterations\":{},\"parallelism\":{},\"tag_length\":{}}}",
        URL_SAFE_NO_PAD.encode(&salt),
        URL_SAFE_NO_PAD.encode(&tag),
        RECOMMENDED.memory_kib,
        RECOMMENDED.iterations,
        RECOMMENDED.parallelism,
        RECOMMENDED.tag_length,
    ).into_bytes())
}

/// Translate and validate the knobs using Argon2's parameter constraints.
fn params(p: &WitParams) -> Result<Params, Error> {
    // argon2 0.5.3 multiplies parallelism before checking its upper bound.
    if p.parallelism > Params::MAX_P_COST {
        return Err(Error::InvalidParams(
            argon2::Error::ThreadsTooMany.to_string(),
        ));
    }

    Params::new(
        p.memory_kib,
        p.iterations,
        p.parallelism,
        Some(p.tag_length as usize),
    )
    .map_err(|e| Error::InvalidParams(format!("{e}")))
}

/// Salt bounds come from Argon2 itself: 8 bytes is the specified minimum, and
/// `argon2::Params` caps it well above anything a caller should send.
fn check_salt(salt: &[u8]) -> Result<(), Error> {
    if salt.len() < argon2::MIN_SALT_LEN {
        return Err(Error::InvalidSalt(format!(
            "salt must be at least {} bytes, got {}",
            argon2::MIN_SALT_LEN,
            salt.len()
        )));
    }
    if salt.len() > argon2::MAX_SALT_LEN {
        return Err(Error::InvalidSalt(format!(
            "salt must be at most {} bytes, got {}",
            argon2::MAX_SALT_LEN,
            salt.len()
        )));
    }
    Ok(())
}

fn check_password(password: &[u8]) -> Result<(), Error> {
    if password.len() > MAX_PASSWORD {
        return Err(Error::InvalidPassword(format!(
            "password must be at most {MAX_PASSWORD} bytes, got {}",
            password.len()
        )));
    }
    Ok(())
}

fn derive_into(
    password: &[u8],
    salt: &[u8],
    algorithm: WitAlgorithm,
    p: &WitParams,
) -> Result<Vec<u8>, Error> {
    check_password(password)?;
    check_salt(salt)?;
    let params = params(p)?;

    let mut tag = vec![0u8; p.tag_length as usize];
    // Version 0x13 (19) is Argon2 v1.3, the only version anything should be
    // producing.
    Argon2::new(algorithm.into(), Version::V0x13, params)
        .hash_password_into(password, salt, &mut tag)
        // Everything reachable here is a parameter problem: the checks above
        // have already cleared the inputs.
        .map_err(|e| Error::InvalidParams(format!("{e}")))?;
    Ok(tag)
}

impl Guest for Component {
    fn enroll(password: Vec<u8>) -> Result<Vec<u8>, Error> {
        let password = Zeroizing::new(password);
        check_password(&password)?;
        #[cfg(target_arch = "wasm32")]
        {
            let salt = wasi::random::random::get_random_bytes(16);
            enrollment_with_salt(&password, salt)
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            Err(Error::InvalidParams(
                "enrollment entropy is only available on wasm32".into(),
            ))
        }
    }

    fn derive(
        password: Vec<u8>,
        salt: Vec<u8>,
        algorithm: WitAlgorithm,
        params: WitParams,
    ) -> Result<Vec<u8>, Error> {
        derive_into(&password, &salt, algorithm, &params)
    }

    fn verify(
        password: Vec<u8>,
        salt: Vec<u8>,
        algorithm: WitAlgorithm,
        params: WitParams,
        expected: Vec<u8>,
    ) -> Result<bool, Error> {
        // Checked before deriving: a length mismatch is a caller bug, and
        // reporting it as `false` would hide it.  The length of the expected
        // tag is not a secret -- it is stored in the clear next to it -- so
        // this branch leaks nothing.
        if expected.len() != params.tag_length as usize {
            return Err(Error::InvalidTag(format!(
                "expected tag of {} bytes, got {}",
                params.tag_length,
                expected.len()
            )));
        }

        let tag = derive_into(&password, &salt, algorithm, &params)?;
        Ok(bool::from(tag.ct_eq(&expected)))
    }

    fn recommended_params() -> WitParams {
        RECOMMENDED
    }
}

export!(Component);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn huge_parallelism_is_rejected_without_panicking() {
        let p = WitParams {
            parallelism: u32::MAX,
            ..RECOMMENDED
        };
        assert!(matches!(params(&p), Err(Error::InvalidParams(_))));
    }

    fn record(password: &[u8], salt: Vec<u8>) -> serde_json::Value {
        let bytes = enrollment_with_salt(password, salt).unwrap();
        serde_json::from_str(std::str::from_utf8(&bytes).unwrap()).unwrap()
    }

    #[test]
    fn enrollment_record_format() {
        let record = record(b"password", vec![0xfb; 16]);
        let fields = record.as_object().unwrap();
        assert_eq!(fields.len(), 7);
        assert_eq!(record["algorithm"], 2);
        assert_eq!(record["memory_kib"], 19456);
        assert_eq!(record["iterations"], 2);
        assert_eq!(record["parallelism"], 1);
        assert_eq!(record["tag_length"], 32);
        for (field, length) in [("salt", 16), ("tag", 32)] {
            let encoded = record[field].as_str().unwrap();
            assert!(encoded
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
            assert_eq!(URL_SAFE_NO_PAD.decode(encoded).unwrap().len(), length);
        }
        assert_eq!(record["salt"], URL_SAFE_NO_PAD.encode([0xfb; 16]));
    }

    #[test]
    fn supplied_salts_produce_distinct_records() {
        let first = record(b"password", vec![1; 16]);
        let second = record(b"password", vec![2; 16]);
        assert_ne!(first["salt"], second["salt"]);
        assert_ne!(first["tag"], second["tag"]);
    }

    #[test]
    fn enrollment_tag_verifies() {
        let record = record(b"password", vec![3; 16]);
        let salt = URL_SAFE_NO_PAD
            .decode(record["salt"].as_str().unwrap())
            .unwrap();
        let tag = URL_SAFE_NO_PAD
            .decode(record["tag"].as_str().unwrap())
            .unwrap();
        assert!(Component::verify(
            b"password".to_vec(),
            salt.clone(),
            WitAlgorithm::Argon2id,
            RECOMMENDED,
            tag.clone()
        )
        .unwrap());
        assert!(!Component::verify(
            b"wrong".to_vec(),
            salt,
            WitAlgorithm::Argon2id,
            RECOMMENDED,
            tag
        )
        .unwrap());
    }

    #[test]
    fn enrollment_rejects_invalid_entropy_and_password() {
        for length in [0, 15, 17] {
            assert!(matches!(
                enrollment_with_salt(b"password", vec![0; length]),
                Err(Error::InvalidParams(_))
            ));
        }
        assert!(matches!(
            enrollment_with_salt(&vec![0; MAX_PASSWORD + 1], vec![0; 16]),
            Err(Error::InvalidPassword(_))
        ));
        assert!(matches!(
            Component::enroll(vec![0; MAX_PASSWORD + 1]),
            Err(Error::InvalidPassword(_))
        ));
    }
}
