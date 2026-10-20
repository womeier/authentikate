import {
  argon2Sync, createPublicKey, generateKeyPairSync, randomBytes,
  sign, timingSafeEqual, verify,
} from 'node:crypto';

export const recommended = Object.freeze({ memoryKib: 19456, iterations: 2, parallelism: 1, tagLength: 32 });
const fail = (tag, val) => { throw val === undefined ? { tag } : { tag, val }; };

export function derive(password, salt, algorithm, params) {
  const { memoryKib, iterations, parallelism, tagLength } = params;
  if (!['argon2d', 'argon2i', 'argon2id'].includes(algorithm)
      || ![memoryKib, iterations, parallelism, tagLength].every(Number.isInteger)
      || parallelism < 1 || parallelism > 4 || memoryKib < 8 * parallelism || memoryKib > 65536
      || iterations < 1 || iterations > 4 || tagLength < 4 || tagLength > 64) {
    fail('invalid-params', 'Unsupported or excessive Argon2 costs');
  }
  if (salt.length < 8 || salt.length > 64) fail('invalid-salt', 'Salt must be 8 to 64 bytes');
  if (password.length > 16384) fail('invalid-password', 'Password exceeds demo limit');
  try {
    return argon2Sync(algorithm, {
      message: password, nonce: salt, memory: memoryKib, passes: iterations,
      parallelism, tagLength,
    });
  } catch {
    fail('invalid-params', 'Native Argon2 derivation failed');
  }
}

export function createProviders() {
  const records = new Map();
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const pubkey = Buffer.from(publicKey.export({ format: 'jwk' }).x, 'base64url');
  const dummySalt = randomBytes(16);
  const config = {
    key: 1, pubkey, iss: Buffer.from('demo'), ttl: 600n, dummySalt,
    dummyTag: derive(randomBytes(32), dummySalt, 'argon2id', recommended),
    dummyParams: { algorithm: 2, ...recommended },
    emailFrom: Buffer.from(process.env.SIGNUP_EMAIL_FROM ?? 'Authentikate <hello@example.test>'),
  };

  class Bucket {
    get(key) {
      const value = records.get(key);
      return value === undefined ? undefined : Uint8Array.from(value);
    }
    set(key, value) { records.set(key, Uint8Array.from(value)); }
  }

  return {
    config,
    imports: {
      'demo:store': { Bucket, open: () => new Bucket() },
      'demo:argon2': {
        derive,
        recommendedParams: () => ({ ...recommended }),
        enroll(password) {
          let salt;
          try { salt = randomBytes(16); } catch { fail('invalid-params', 'Entropy unavailable'); }
          const tag = derive(password, salt, 'argon2id', recommended);
          return Buffer.from(JSON.stringify({
            algorithm: 2, memory_kib: 19456, iterations: 2, parallelism: 1, tag_length: 32,
            salt: salt.toString('base64url'), tag: tag.toString('base64url'),
          }));
        },
        verify(password, salt, algorithm, params, expected) {
          if (expected.length !== params.tagLength) fail('invalid-tag', 'Tag length mismatch');
          return timingSafeEqual(derive(password, salt, algorithm, params), expected);
        },
      },
      'demo:ed25519': {
        publicKey(key) {
          if (key !== 1) fail('invalid-key');
          return Uint8Array.from(pubkey);
        },
        sign(key, message) {
          if (key !== 1) fail('invalid-key');
          try { return sign(null, message, privateKey); }
          catch { fail('key-store-unavailable'); }
        },
        verify(key, message, signature) {
          if (key.length !== 32) fail('invalid-public-key', 'Expected 32 bytes');
          if (signature.length !== 64) fail('invalid-signature', 'Expected 64 bytes');
          let parsed;
          try {
            parsed = createPublicKey({
              key: { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(key).toString('base64url') },
              format: 'jwk',
            });
          } catch { fail('invalid-public-key', 'Invalid Ed25519 public key'); }
          return verify(null, message, parsed, signature);
        },
      },
    },
  };
}
