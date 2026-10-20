import assert from 'node:assert/strict';
import { once } from 'node:events';
import { request as httpRequest } from 'node:http';
import { createDemoServer } from '../web/server.mjs';
import { createProviders, derive, recommended } from '../web/providers.mjs';

// Invalid costs must be rejected before any expensive native work.
assert.throws(() => derive(Buffer.from('password'), Buffer.alloc(16), 'argon2id', {
  ...recommended, memoryKib: 0xffffffff,
}), error => error.tag === 'invalid-params');
assert.throws(() => derive(Buffer.from('password'), Buffer.alloc(2), 'argon2id', recommended),
  error => error.tag === 'invalid-salt');
const { imports, config } = createProviders();
const argon = imports['demo:argon2'];
const password = Buffer.from('provider-test-password');
const record = JSON.parse(Buffer.from(argon.enroll(password)));
assert.equal(record.email, undefined);
assert.equal(record.password, undefined);
assert.equal(Buffer.from(record.salt, 'base64url').length, 16);
assert.equal(argon.verify(password, Buffer.from(record.salt, 'base64url'), 'argon2id', recommended,
  Buffer.from(record.tag, 'base64url')), true);
assert.equal(argon.verify(Buffer.from('wrong'), Buffer.from(record.salt, 'base64url'), 'argon2id', recommended,
  Buffer.from(record.tag, 'base64url')), false);
assert.equal(config.pubkey.length, 32);
const ed = imports['demo:ed25519'];
const signature = ed.sign(1, password);
assert.equal(ed.verify(config.pubkey, password, signature), true);
assert.throws(() => ed.sign(2, password), error => error.tag === 'invalid-key');
console.log('web: native Argon2 and Ed25519 provider checks passed');

const server = await createDemoServer();
server.listen(0, '127.0.0.1');
await once(server, 'listening');
const base = `http://127.0.0.1:${server.address().port}`;
async function post(path, body, expected) {
  const response = await fetch(`${base}${path}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  });
  const result = await response.json();
  assert.equal(response.status, expected, `${path}: ${JSON.stringify(result)}`);
  assert.equal(response.headers.get('access-control-allow-origin'), null);
  return result;
}

try {
  const page = await fetch(base);
  assert.equal(page.status, 200);
  assert.match(await page.text(), /Identity Workbench/);
  assert.match(page.headers.get('content-security-policy'), /default-src 'self'/);
  for (const asset of ['/style.css', '/app.js']) assert.equal((await fetch(base + asset)).status, 200);
  await post('/api/no-route', {}, 404);
  await post('/api/login', 'x'.repeat(16385), 413);
  assert.equal((await fetch(`${base}/api/login`)).status, 405);
  assert.equal((await fetch(`${base}/package.json`)).status, 404);
  assert.equal((await fetch(`${base}/api/login`, { method: 'POST', body: '{}' })).status, 415);
  assert.equal((await fetch(`${base}/api/login`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Origin: 'https://untrusted.test' }, body: '{}',
  })).status, 403);
  for (const [options, expected] of [
    [{ headers: { Host: `rebound.test:${server.address().port}` } }, 403],
    [{ method: 'POST', path: '/api/login', headers: {
      Host: `rebound.test:${server.address().port}`, Origin: `http://rebound.test:${server.address().port}`,
      'Content-Type': 'application/json',
    } }, 403],
    [{ headers: { Host: '127.0.0.1:1' } }, 403],
    [{ path: 'http://rebound.test/' }, 400],
    [{ path: '//rebound.test/' }, 400],
    [{ headers: { Host: `localhost:${server.address().port}` } }, 200],
  ]) {
    await new Promise((resolve, reject) => {
      const request = httpRequest(base, options, response => {
        response.resume();
        response.on('end', () => {
          try { assert.equal(response.statusCode, expected); resolve(); } catch (error) { reject(error); }
        });
      });
      request.on('error', reject);
      request.end();
    });
  }
  // Exercise the streaming limit with no Content-Length header.
  await new Promise((resolve, reject) => {
    const request = httpRequest(`${base}/api/login`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
    }, response => {
      response.resume();
      response.on('end', () => {
        try { assert.equal(response.statusCode, 413); resolve(); } catch (error) { reject(error); }
      });
    });
    request.on('error', reject);
    request.write('x'.repeat(8192));
    request.end('x'.repeat(8193));
  });
  console.log('web: static assets, routes, content type, host, origin and body limits passed');
  const credentials = { email: 'workbench@example.test', password: 'a-local-demo-password' };
  assert.deepEqual(await post('/api/signup', credentials, 201), {});
  await post('/api/signup', credentials, 409);
  const login = await post('/api/login', credentials, 200);
  assert.equal(typeof login.token, 'string');
  const claims = JSON.parse(Buffer.from(login.token.split('.')[1], 'base64url'));
  assert.equal(claims.iss, 'demo');
  assert.equal(claims.exp - claims.iat, 600);
  assert.equal(claims.sub, credentials.email);
  await post('/api/login', { ...credentials, password: 'incorrect' }, 401);
  await post('/api/login', { email: 'unknown@example.test', password: 'incorrect' }, 401);
  const validation = await post('/api/validate', { token: login.token }, 200);
  assert.equal(validation.valid, true);
  assert.equal(validation.claims.sub, credentials.email);
  assert.equal(validation.claims.iss, 'demo');
  assert.equal(validation.claims.iat, claims.iat);
  assert.equal(validation.claims.exp, claims.exp);
  assert.equal(validation.claims.exp - validation.claims.iat, 600);
  const parts = login.token.split('.');
  parts[2] = (parts[2][0] === 'A' ? 'B' : 'A') + parts[2].slice(1);
  assert.deepEqual(await post('/api/validate', { token: parts.join('.') }, 200), { valid: false });
  assert.deepEqual(await post('/api/validate', { token: 'not.a.token' }, 200), { valid: false });
  for (const endpoint of ['signup', 'login', 'validate']) {
    await post(`/api/${endpoint}`, '{', 400);
    await post(`/api/${endpoint}`, {}, 400);
  }
  const duplicates = await Promise.all([0, 1].map(() => fetch(`${base}/api/signup`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ...credentials, email: 'concurrent@example.test' }),
  })));
  assert.deepEqual(duplicates.map(response => response.status).sort(), [201, 409]);
  await Promise.all(duplicates.map(response => response.arrayBuffer()));
  console.log('web: actual component signup/login/validate, returned claims, tampered tokens, malformed input and concurrent duplicates passed');
} finally {
  server.closeAllConnections();
  await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
}
