//! Ed25519 signatures, as a WebAssembly component.
//!
//! The component imports nothing: no clock, no random source, no I/O.  Every
//! instance owns its private keys. The host provisions it before serving
//! requests and passes only u32 handles to the service. Handles and keys do
//! not survive instance destruction; a per-request instance needs provisioning
//! on every request. Signing is deterministic, but key import is stateful.
//!
//! See `../wit/ed25519.wit` for the interface and why it is shaped this way.
//!
//! # On the library underneath
//!
//! This is ed25519-dalek, for consistency with `../argon2`: one ecosystem,
//! one set of build quirks, and nothing to decide twice.  The intended
//! destination is still libcrux, which is itself formally verified and ships
//! a Wasm-friendly build -- the reason `PLAN.md` names it.  Argon2 could not
//! go there (libcrux has no Argon2), but Ed25519 can, and swapping it is a
//! change behind this file: the WIT interface is library-agnostic, so nothing
//! above the component boundary -- and in particular nothing in `components/service/theories/`,
//! where the axiom is stated -- has to move when it happens.

// std, not no_std: on wasm32-unknown-unknown the standard library's I/O is
// stubbed out and imports nothing, so using it costs no imports and saves
// hand-rolling a panic handler and a global allocator.
use ed25519_dalek::Signer;
use ed25519_dalek::{
    Signature, SigningKey, VerifyingKey, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, SIGNATURE_LENGTH,
};
use std::sync::Mutex;
use zeroize::Zeroizing;

wit_bindgen::generate!({
    world: "signing",
    path: "../wit",
});

use exports::authentikate::crypto::ed25519::{Error, Guest};

struct Component;

const MAX_KEYS: usize = 1024;

// Append-only: bounding the store also bounds handles, with no wraparound or
// stale handle reuse. No key material leaves this component through the ABI.
struct KeyStore {
    keys: Vec<SigningKey>,
}

impl KeyStore {
    fn insert(&mut self, key: SigningKey) -> Result<u32, Error> {
        if self.keys.len() >= MAX_KEYS {
            return Err(Error::KeyStoreFull);
        }
        self.keys.push(key);
        Ok(self.keys.len() as u32)
    }

    fn get(&self, handle: u32) -> Result<&SigningKey, Error> {
        let index = handle.checked_sub(1).ok_or(Error::InvalidKey)?;
        self.keys.get(index as usize).ok_or(Error::InvalidKey)
    }
}

static KEYS: Mutex<KeyStore> = Mutex::new(KeyStore { keys: Vec::new() });

/// A private key is a 32-byte seed; the key pair is derived from it.
///
/// `SigningKey::from_bytes` cannot fail -- every 32-byte string is a seed --
/// so the only thing to check is the length.  The seed is wiped on drop by
/// dalek's `zeroize` feature. Borrowing the seed avoids an extra stack copy;
/// the imported buffer is separately wiped by `Zeroizing` in `import_key`.
fn signing_key(bytes: &[u8]) -> Result<SigningKey, Error> {
    let seed: &[u8; SECRET_KEY_LENGTH] = bytes.try_into().map_err(|_| {
        Error::InvalidPrivateKey(format!(
            "private key must be {SECRET_KEY_LENGTH} bytes, got {}",
            bytes.len()
        ))
    })?;
    Ok(SigningKey::from_bytes(seed))
}

/// A public key is a compressed curve point, and not every 32-byte string is
/// one: decompression is the second check after the length.
fn verifying_key(bytes: &[u8]) -> Result<VerifyingKey, Error> {
    let encoded: [u8; PUBLIC_KEY_LENGTH] = bytes.try_into().map_err(|_| {
        Error::InvalidPublicKey(format!(
            "public key must be {PUBLIC_KEY_LENGTH} bytes, got {}",
            bytes.len()
        ))
    })?;
    VerifyingKey::from_bytes(&encoded)
        .map_err(|e| Error::InvalidPublicKey(format!("not a point on the curve: {e}")))
}

/// `Signature::from_bytes` cannot fail either: it splits 64 bytes into `R`
/// and `s` and leaves judgement to the verifier, which is where strictness
/// belongs.  So, again, only the length is checked here.
fn signature(bytes: &[u8]) -> Result<Signature, Error> {
    let encoded: [u8; SIGNATURE_LENGTH] = bytes.try_into().map_err(|_| {
        Error::InvalidSignature(format!(
            "signature must be {SIGNATURE_LENGTH} bytes, got {}",
            bytes.len()
        ))
    })?;
    Ok(Signature::from_bytes(&encoded))
}

impl Guest for Component {
    fn import_key(private_key: Vec<u8>) -> Result<u32, Error> {
        let private_key = Zeroizing::new(private_key);
        let key = signing_key(&private_key)?;
        KEYS.lock()
            .map_err(|_| Error::KeyStoreUnavailable)?
            .insert(key)
    }

    fn public_key(key: u32) -> Result<Vec<u8>, Error> {
        Ok(KEYS
            .lock()
            .map_err(|_| Error::KeyStoreUnavailable)?
            .get(key)?
            .verifying_key()
            .to_bytes()
            .to_vec())
    }

    fn sign(key: u32, message: Vec<u8>) -> Result<Vec<u8>, Error> {
        Ok(KEYS
            .lock()
            .map_err(|_| Error::KeyStoreUnavailable)?
            .get(key)?
            .sign(&message)
            .to_bytes()
            .to_vec())
    }

    fn verify(
        public_key: Vec<u8>,
        message: Vec<u8>,
        signature_bytes: Vec<u8>,
    ) -> Result<bool, Error> {
        let key = verifying_key(&public_key)?;
        let sig = signature(&signature_bytes)?;

        // `verify_strict` rather than `verify`: it rejects non-canonical
        // encodings of `R` and of the public key, and signatures under a
        // small-order key.  Those rejections come back as `false` rather than
        // as an error -- a small-order key is a well-formed point, so the
        // question was asked and the answer is no.  `verify` would accept
        // some of them, which is how two verifiers end up disagreeing about
        // the same token.
        Ok(key.verify_strict(&message, &sig).is_ok())
    }
}

export!(Component);

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8032 section 7.1 gives its vectors in hex; keeping them in that
    /// form is what makes them checkable against the document.
    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 8032, section 7.1, TEST 1: the empty message.
    const SEED_1: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const PUBLIC_1: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const SIG_1: &str = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
                         5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

    /// TEST 2: a one-byte message.
    const SEED_2: &str = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
    const PUBLIC_2: &str = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
    const MSG_2: &str = "72";
    const SIG_2: &str = "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
                         085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00";

    #[test]
    fn public_key_matches_rfc_vectors() {
        let key_1 = Component::import_key(hex(SEED_1)).unwrap();
        let key_2 = Component::import_key(hex(SEED_2)).unwrap();
        assert_ne!(key_1, key_2);
        assert_eq!(Component::public_key(key_1).unwrap(), hex(PUBLIC_1));
        assert_eq!(Component::public_key(key_2).unwrap(), hex(PUBLIC_2));
    }

    #[test]
    fn signatures_match_rfc_vectors() {
        let key_1 = Component::import_key(hex(SEED_1)).unwrap();
        let key_2 = Component::import_key(hex(SEED_2)).unwrap();
        assert_eq!(Component::sign(key_1, vec![]).unwrap(), hex(SIG_1));
        assert_eq!(Component::sign(key_2, hex(MSG_2)).unwrap(), hex(SIG_2));
        assert_eq!(Component::sign(key_1, vec![]).unwrap(), hex(SIG_1));
    }

    #[test]
    fn invalid_handles_are_rejected() {
        for key in [0, MAX_KEYS as u32 + 1, u32::MAX] {
            assert!(matches!(Component::public_key(key), Err(Error::InvalidKey)));
            assert!(matches!(
                Component::sign(key, vec![]),
                Err(Error::InvalidKey)
            ));
        }
    }

    #[test]
    fn handles_are_bounded_and_instance_local() {
        let mut store = KeyStore { keys: Vec::new() };
        assert!(matches!(store.get(1), Err(Error::InvalidKey)));
        for expected in 1..=MAX_KEYS as u32 {
            assert_eq!(
                store.insert(signing_key(&hex(SEED_1)).unwrap()).unwrap(),
                expected
            );
        }
        assert!(matches!(
            store.insert(signing_key(&hex(SEED_2)).unwrap()),
            Err(Error::KeyStoreFull)
        ));
        assert_eq!(
            store.get(1).unwrap().verifying_key().to_bytes().to_vec(),
            hex(PUBLIC_1)
        );
        assert_eq!(
            store
                .get(MAX_KEYS as u32)
                .unwrap()
                .verifying_key()
                .to_bytes()
                .to_vec(),
            hex(PUBLIC_1)
        );
        assert!(matches!(
            store.get(MAX_KEYS as u32 + 1),
            Err(Error::InvalidKey)
        ));
        let fresh_store = KeyStore { keys: Vec::new() };
        assert!(matches!(fresh_store.get(1), Err(Error::InvalidKey)));
    }

    #[test]
    fn verify_accepts_the_rfc_vectors() {
        assert!(Component::verify(hex(PUBLIC_1), vec![], hex(SIG_1)).unwrap());
        assert!(Component::verify(hex(PUBLIC_2), hex(MSG_2), hex(SIG_2)).unwrap());
    }

    #[test]
    fn verify_rejects_a_wrong_message_and_a_wrong_key() {
        // Same signature, different message.
        assert!(!Component::verify(hex(PUBLIC_2), hex("73"), hex(SIG_2)).unwrap());
        // Same message, the other key pair's public key.
        assert!(!Component::verify(hex(PUBLIC_1), hex(MSG_2), hex(SIG_2)).unwrap());
    }

    #[test]
    fn verify_rejects_a_tampered_signature() {
        let mut sig = hex(SIG_2);
        sig[0] ^= 1;
        assert!(!Component::verify(hex(PUBLIC_2), hex(MSG_2), sig).unwrap());
    }

    /// A wrong-shaped input is an error, not a `false`: the question was never
    /// asked.
    #[test]
    fn lengths_are_checked() {
        assert!(matches!(
            Component::import_key(vec![0; 31]),
            Err(Error::InvalidPrivateKey(_))
        ));
        assert!(matches!(
            Component::import_key(vec![0; 33]),
            Err(Error::InvalidPrivateKey(_))
        ));
        assert!(matches!(
            Component::verify(vec![0; 31], vec![], hex(SIG_1)),
            Err(Error::InvalidPublicKey(_))
        ));
        assert!(matches!(
            Component::verify(hex(PUBLIC_1), vec![], vec![0; 63]),
            Err(Error::InvalidSignature(_))
        ));
    }

    /// 32 bytes that do not decompress to a point on the curve: a length
    /// check alone would let this through.  `y = 2` is the smallest such.
    #[test]
    fn a_public_key_off_the_curve_is_rejected() {
        let off_curve = hex("0200000000000000000000000000000000000000000000000000000000000000");
        assert!(matches!(
            Component::verify(off_curve, vec![], hex(SIG_1)),
            Err(Error::InvalidPublicKey(_))
        ));
    }

    /// The identity point -- `y = 1` with the sign bit set -- is a valid
    /// point of order 1, so it decompresses and the question gets asked; the
    /// strict check is what then answers no.  This is the case `verify`
    /// rather than `verify_strict` would wave through, so it is the one worth
    /// pinning down.
    #[test]
    fn a_small_order_public_key_verifies_nothing() {
        let identity = hex("0100000000000000000000000000000000000000000000000000000000000080");
        assert!(!Component::verify(identity, vec![], hex(SIG_1)).unwrap());
    }
}
