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
//! Libcrux supplies key derivation, signing, and verification. The wrapper
//! additionally rejects small-order public keys and signature points, and
//! stores private seeds in zeroizing buffers. Libcrux 0.0.10 does not explicitly
//! wipe its internal expanded-key temporaries; seed wiping is not full secret
//! erasure. Libcrux's verification guarantees do not extend to this wrapper,
//! the Wasm toolchain, or the whole service.

// std, not no_std: on wasm32-unknown-unknown the standard library's I/O is
// stubbed out and imports nothing, so using it costs no imports and saves
// hand-rolling a panic handler and a global allocator.
use std::sync::Mutex;
use zeroize::Zeroizing;

wit_bindgen::generate!({
    world: "signing",
    path: "../wit",
});

use exports::authentikate::crypto::ed25519::{Error, Guest};

struct Component;

const MAX_KEYS: usize = 1024;
const SECRET_KEY_LENGTH: usize = 32;
const PUBLIC_KEY_LENGTH: usize = 32;
const SIGNATURE_LENGTH: usize = 64;
type SigningKey = Zeroizing<[u8; SECRET_KEY_LENGTH]>;

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
/// Every 32-byte string is a seed. Both the stored seed and the imported
/// buffer are wiped on drop; libcrux receives a borrowed seed.
fn signing_key(bytes: &[u8]) -> Result<SigningKey, Error> {
    let seed: &[u8; SECRET_KEY_LENGTH] = bytes.try_into().map_err(|_| {
        Error::InvalidPrivateKey(format!(
            "private key must be {SECRET_KEY_LENGTH} bytes, got {}",
            bytes.len()
        ))
    })?;
    let mut key = Zeroizing::new([0; SECRET_KEY_LENGTH]);
    key.copy_from_slice(seed);
    Ok(key)
}

fn verifying_key(bytes: &[u8]) -> Result<&[u8; PUBLIC_KEY_LENGTH], Error> {
    bytes.try_into().map_err(|_| {
        Error::InvalidPublicKey(format!(
            "public key must be {PUBLIC_KEY_LENGTH} bytes, got {}",
            bytes.len()
        ))
    })
}

fn signature(bytes: &[u8]) -> Result<&[u8; SIGNATURE_LENGTH], Error> {
    bytes.try_into().map_err(|_| {
        Error::InvalidSignature(format!(
            "signature must be {SIGNATURE_LENGTH} bytes, got {}",
            bytes.len()
        ))
    })
}

fn public_key(seed: &[u8; SECRET_KEY_LENGTH]) -> [u8; PUBLIC_KEY_LENGTH] {
    let mut public = [0; PUBLIC_KEY_LENGTH];
    libcrux_ed25519::secret_to_public(&mut public, seed);
    public
}

fn is_small_order(encoded: &[u8]) -> bool {
    // The eight torsion points have five distinct y coordinates. Ignore the
    // x sign bit to cover both signs. Libcrux rejects noncanonical encodings.
    // See libsodium 1.0.18's ge25519_has_small_order blocklist in ed25519_ref10.c.
    const ORDER_EIGHT_Y: [[u8; 32]; 2] = [
        [
            0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef,
            0x98, 0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88,
            0x6d, 0x53, 0xfc, 0x05,
        ],
        [
            0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10,
            0x67, 0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77,
            0x92, 0xac, 0x03, 0x7a,
        ],
    ];
    let mut y = [0; 32];
    y.copy_from_slice(encoded);
    y[31] &= 0x7f;
    let zero_or_one = y[0] <= 1 && y[1..].iter().all(|&b| b == 0);
    let minus_one = y[0] == 0xec && y[1..31].iter().all(|&b| b == 0xff) && y[31] == 0x7f;
    zero_or_one || minus_one || ORDER_EIGHT_Y.contains(&y)
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
        let keys = KEYS.lock().map_err(|_| Error::KeyStoreUnavailable)?;
        Ok(public_key(keys.get(key)?).to_vec())
    }

    fn sign(key: u32, message: Vec<u8>) -> Result<Vec<u8>, Error> {
        let keys = KEYS.lock().map_err(|_| Error::KeyStoreUnavailable)?;
        let seed = keys.get(key)?;
        // This error is unreachable on wasm32: a slice fits in u32.
        libcrux_ed25519::sign(&message, seed)
            .map(|signature| signature.to_vec())
            .map_err(|_| Error::InvalidSignature("message exceeds u32 length limit".into()))
    }

    fn verify(
        public_key: Vec<u8>,
        message: Vec<u8>,
        signature_bytes: Vec<u8>,
    ) -> Result<bool, Error> {
        let key = verifying_key(&public_key)?;
        let sig = signature(&signature_bytes)?;

        if is_small_order(key) || is_small_order(&sig[..32]) {
            return Ok(false);
        }
        Ok(libcrux_ed25519::verify(&message, key, sig).is_ok())
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
        assert_eq!(public_key(store.get(1).unwrap()).to_vec(), hex(PUBLIC_1));
        assert_eq!(
            public_key(store.get(MAX_KEYS as u32).unwrap()).to_vec(),
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
        assert!(!Component::verify(off_curve, vec![], hex(SIG_1)).unwrap());
    }

    /// Identity-key forgeries pass libcrux's equation without our extra check.
    #[test]
    fn a_small_order_public_key_verifies_nothing() {
        let identity = hex("0100000000000000000000000000000000000000000000000000000000000000");
        let mut forged = vec![0; 64];
        forged[..32].copy_from_slice(&identity);
        assert!(libcrux_ed25519::verify(
            b"forged",
            identity.as_slice().try_into().unwrap(),
            forged.as_slice().try_into().unwrap()
        )
        .is_ok());
        assert!(!Component::verify(identity, b"forged".to_vec(), forged).unwrap());
    }

    #[test]
    fn small_order_points_are_rejected_for_both_signs() {
        for encoded in [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        ] {
            for sign in [0, 0x80] {
                let mut point = hex(encoded);
                point[31] |= sign;
                assert!(is_small_order(&point));
                assert!(!Component::verify(point.clone(), vec![], hex(SIG_1)).unwrap());
                let mut sig = hex(SIG_1);
                sig[..32].copy_from_slice(&point);
                assert!(!Component::verify(hex(PUBLIC_1), vec![], sig).unwrap());
            }
        }
        assert!(!is_small_order(&hex(PUBLIC_1)));
        assert!(!is_small_order(&hex(SIG_1)[..32]));
    }

    #[test]
    fn noncanonical_points_and_scalars_are_rejected() {
        for encoded in [
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        ] {
            for sign in [0, 0x80] {
                let mut point = hex(encoded);
                point[31] |= sign;
                assert!(!Component::verify(point.clone(), vec![], hex(SIG_1)).unwrap());
                let mut sig = hex(SIG_1);
                sig[..32].copy_from_slice(&point);
                assert!(!Component::verify(hex(PUBLIC_1), vec![], sig).unwrap());
            }
        }
        let mut sig = hex(SIG_1);
        // Adding the subgroup order to a valid S preserves the equation, but
        // must fail canonical-scalar validation rather than being reduced.
        let order = hex("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
        let mut carry = 0u16;
        for (s, l) in sig[32..].iter_mut().zip(order) {
            let sum = *s as u16 + l as u16 + carry;
            *s = sum as u8;
            carry = sum >> 8;
        }
        assert!(!Component::verify(hex(PUBLIC_1), vec![], sig).unwrap());
    }
}
