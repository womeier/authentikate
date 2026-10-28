// Real CLI integration tests; no npm packages or Wasmtime library embedding.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { chmod, mkdir, mkdtemp, open, readFile, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import http from 'node:http';
import net from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import test from 'node:test';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const component = resolve(root, process.env.APP_COMPONENT ?? 'build/app.component.wasm');
const wasmtime = process.env.WASMTIME ?? 'wasmtime';
const issuer = 'runtime-integration-tests';
const ttl = 137;
const sender = 'Runtime Tests <runtime@example.test>';
const credentials = { email: 'socket@example.test', password: 'not-printed-password' };

async function fixture(t) {
  const directory = await mkdtemp(join(tmpdir(), 'authentikate-http-'));
  await chmod(directory, 0o700);
  t.after(() => rm(directory, { recursive: true, force: true }));
  for (const name of ['accounts', 'config']) await mkdir(join(directory, name), { mode: 0o700 });
  const key = randomBytes(32);
  await writeFile(join(directory, 'config/signing.key'), `${key.toString('base64url')}\n`, { mode: 0o600 });
  return { directory, key };
}

async function unusedPort() {
  const socket = net.createServer();
  await new Promise((resolve, reject) => {
    socket.once('error', reject);
    socket.listen(0, '127.0.0.1', resolve);
  });
  const { port } = socket.address();
  await new Promise((resolve, reject) => socket.close(error => error ? reject(error) : resolve()));
  return port;
}

async function start(t, fixture, { config = value => value, stdout = 'pipe' } = {}) {
  const port = await unusedPort();
  const authority = `127.0.0.1:${port}`;
  const settings = config({
    service: { issuer, token_ttl_seconds: ttl, email_from: sender },
    policy: { approved_origin: null, approved_authorities: [authority] },
  });
  if (settings !== undefined) {
    await writeFile(join(fixture.directory, 'config/config.json'),
      typeof settings === 'string' ? settings : JSON.stringify(settings), { mode: 0o600 });
  }
  const args = ['serve', '--addr', authority,
    '-S', 'cli=y,inherit-network=n,allow-ip-name-lookup=n,tcp=n,udp=n,inherit-env=n',
    '--max-instance-reuse-count', '1', '--max-concurrent-requests', '1',
    '--max-concurrent-connections', '8', '--no-logging-prefix',
    '-W', 'fuel=2000000000,max-memory-size=134217728,max-memories=8,max-instances=32,max-tables=16,max-wasm-stack=8388608,async-stack-size=16777216',
    '--dir', 'accounts::/accounts', '--dir', 'config::/config', component];
  const child = spawn(wasmtime, args, {
    cwd: fixture.directory, stdio: ['ignore', stdout, 'pipe'],
  });
  let output = '', errors = '', spawnError;
  child.stdout?.setEncoding('utf8').on('data', data => { output += data; });
  child.stderr.setEncoding('utf8').on('data', data => { errors += data; });
  child.on('error', error => { spawnError = error; });
  const closed = new Promise(resolve => child.once('close', resolve));
  async function stop() {
    if (child.exitCode === null && child.signalCode === null && !spawnError) child.kill('SIGTERM');
    const timer = setTimeout(() => child.kill('SIGKILL'), 3000);
    try { await closed; } finally { clearTimeout(timer); }
  }
  t.after(stop);
  const diagnostics = () => `${wasmtime} ${args.join(' ')}\n${errors}`;
  // Probe TCP, not HTTP: invalid configuration must be tested on the first request,
  // and readiness must not depend on Wasmtime's human-readable log format.
  const deadline = Date.now() + 60_000;
  while (true) {
    if (spawnError) throw new Error(`Cannot spawn ${wasmtime}: ${spawnError.message}`);
    if (child.exitCode !== null || child.signalCode !== null) throw new Error(diagnostics());
    try {
      await new Promise((resolve, reject) => {
        const socket = net.connect({ host: '127.0.0.1', port });
        socket.once('error', reject);
        socket.once('connect', () => { socket.destroy(); resolve(); });
      });
      break;
    } catch {
      if (Date.now() > deadline) throw new Error(`Server readiness timed out\n${diagnostics()}`);
      await delay(50);
    }
  }
  function request(path, { method = 'GET', headers = {}, body } = {}) {
    return new Promise((resolve, reject) => {
      const req = http.request({ host: '127.0.0.1', port, path, method, agent: false,
        headers: { connection: 'close', ...headers } }, response => {
        const chunks = [];
        response.on('data', chunk => chunks.push(chunk));
        response.on('error', reject);
        response.on('end', () => resolve({ status: response.statusCode,
          headers: response.headers, body: Buffer.concat(chunks).toString('utf8') }));
      });
      req.setTimeout(30_000, () => req.destroy(new Error(`HTTP timeout\n${diagnostics()}`)));
      req.on('error', reject);
      req.end(body);
    });
  }
  async function post(path, value, expected = 200) {
    const body = JSON.stringify(value);
    const response = await request(path, { method: 'POST', body, headers: {
      'content-type': 'application/json', 'content-length': Buffer.byteLength(body),
    } });
    assert.equal(response.status, expected, `${response.body}\n${diagnostics()}`);
    assert.equal(response.headers['access-control-allow-origin'], undefined);
    return JSON.parse(response.body);
  }
  function raw(message) {
    return new Promise((resolve, reject) => {
      const socket = net.connect({ host: '127.0.0.1', port });
      const chunks = [];
      socket.setTimeout(30_000, () => socket.destroy(new Error('Raw HTTP timeout')));
      socket.on('error', reject);
      socket.on('data', chunk => chunks.push(chunk));
      socket.on('connect', () => socket.write(message));
      socket.on('end', () => {
        const response = Buffer.concat(chunks).toString('utf8');
        const status = Number(/^HTTP\/1\.[01] (\d{3})/.exec(response)?.[1]);
        if (!status) reject(new Error(`Missing HTTP response: ${response}\n${diagnostics()}`));
        else resolve({ status, body: response });
      });
    });
  }
  return { authority, request, post, raw, stop, diagnostics,
    get stdout() { return output; }, get stderr() { return errors; } };
}

function sign(key, claims, header = { alg: 'HS256', typ: 'JWT' }) {
  const input = [header, claims].map(value => Buffer.from(JSON.stringify(value)).toString('base64url')).join('.');
  return `${input}.${createHmac('sha256', key).update(input).digest('base64url')}`;
}

test('real HTTP policy, body limits, accounts, HS256, email and restart persistence', { timeout: 180_000 }, async t => {
  await readFile(component); // Fail explicitly rather than silently skipping a missing build.
  const f = await fixture(t);
  const server = await start(t, f);
  const page = await server.request('/');
  assert.equal(page.status, 200, server.diagnostics());
  assert.match(page.body, /<title>Authentikate \/ Authentication Demo<\/title>/);
  assert.equal(page.headers['cache-control'], 'no-store');
  assert.equal(page.headers['x-content-type-options'], 'nosniff');
  assert.equal(page.headers['referrer-policy'], 'no-referrer');
  assert.ok(page.headers['content-security-policy']);
  for (const [target, host, expected] of [
    ['//rebound.test/', server.authority, 400],
    ['http://rebound.test/', server.authority, 403],
    ['/', 'rebound.test', 403],
    ['/', '127.0.0.1', 403],
    ['/', '127.0.0.1:1', 403],
  ]) {
    assert.equal((await server.raw(`GET ${target} HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n\r\n`)).status, expected);
  }
  for (const origin of ['https://untrusted.test', 'null', `https://${server.authority}`]) {
    assert.equal((await server.request('/api/login', { method: 'POST', headers: { origin } })).status, 403);
  }
  assert.equal((await server.request('/', { headers: { origin: `http://${server.authority}` } })).status, 200);
  assert.equal((await server.raw(`GET / HTTP/1.1\r\nHost: ${server.authority}\r\nOrigin: http://${server.authority}\r\nOrigin: http://${server.authority}\r\nConnection: close\r\n\r\n`)).status, 403);
  assert.equal((await server.request('/api/login')).status, 405);
  assert.equal((await server.request('/missing')).status, 404);
  assert.equal((await server.request('/api/login', { method: 'POST', body: '{}' })).status, 415);
  await server.post('/api/login', {}, 400);
  const prefix = `POST /api/login HTTP/1.1\r\nHost: ${server.authority}\r\nContent-Type: application/json\r\nConnection: close\r\n`;
  const boundary = await server.request('/api/validate', { method: 'POST',
    headers: { 'content-type': 'application/json', 'content-length': 16384 },
    body: JSON.stringify({ token: 'invalid' }).padEnd(16384, ' ') });
  assert.equal(boundary.status, 200, `the exact 16 KiB boundary must remain accepted\n${server.diagnostics()}`);
  assert.equal(JSON.parse(boundary.body).valid, false);
  assert.equal((await server.raw(`${prefix}Content-Length: 16385\r\n\r\n`)).status, 413);
  const chunk = 'x'.repeat(8192);
  assert.equal((await server.raw(`${prefix}Transfer-Encoding: chunked\r\n\r\n2000\r\n${chunk}\r\n2000\r\n${chunk}\r\n1\r\nx\r\n0\r\n\r\n`)).status, 413);
  const validBody = JSON.stringify({ token: 'invalid' });
  const chunked = await server.raw(`POST /api/validate HTTP/1.1\r\nHost: ${server.authority}\r\nContent-Type: application/json\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n${validBody.length.toString(16)}\r\n${validBody}\r\n0\r\n\r\n`);
  assert.equal(chunked.status, 200);
  await server.post('/api/login', credentials, 401);
  await server.post('/api/signup', credentials, 201);
  await server.post('/api/signup', credentials, 409);
  await server.post('/api/login', { ...credentials, password: 'wrong-password' }, 401);
  const before = Math.floor(Date.now() / 1000);
  const { token } = await server.post('/api/login', credentials);
  const after = Math.floor(Date.now() / 1000);
  assert.equal((await server.post('/api/validate', { token })).valid, true);
  const segments = token.split('.');
  assert.equal(segments.length, 3);
  assert.deepEqual(JSON.parse(Buffer.from(segments[0], 'base64url')), { alg: 'HS256', typ: 'JWT' });
  const signature = Buffer.from(segments[2], 'base64url');
  const expected = createHmac('sha256', f.key).update(`${segments[0]}.${segments[1]}`).digest();
  assert.equal(signature.length, expected.length);
  assert.ok(timingSafeEqual(signature, expected), 'Node must verify the component HS256 signature');
  const claims = JSON.parse(Buffer.from(segments[1], 'base64url'));
  assert.equal(claims.iss, issuer);
  assert.ok(claims.iat >= before && claims.iat <= after);
  assert.equal(claims.exp - claims.iat, ttl);
  assert.equal(claims.sub, credentials.email);
  const external = sign(f.key, { iss: issuer, exp: claims.exp, sub: claims.sub, iat: claims.iat });
  assert.notEqual(external, token, 'independently encoded payload must differ from the minted token');
  assert.equal((await server.post('/api/validate', { token: external })).valid, true);
  for (const invalid of [
    sign(randomBytes(32), claims), sign(f.key, { ...claims, iss: 'wrong-issuer' }),
    sign(f.key, { ...claims, iat: 1, exp: 2 }),
    sign(f.key, claims, { alg: 'none', typ: 'JWT' }),
    `${segments[0]}.${Buffer.from(JSON.stringify({ ...claims, sub: 'tampered' })).toString('base64url')}.${segments[2]}`,
    'not-a-token',
  ]) assert.equal((await server.post('/api/validate', { token: invalid })).valid, false);
  await server.stop();
  const emails = server.stdout.trim().split('\n').filter(Boolean).map(line => JSON.parse(line));
  assert.deepEqual(emails, [{ backend: 'stdout', email: {
    from: sender, to: [credentials.email], subject: 'Welcome to Authentikate',
    text: 'Your Authentikate account has been created. Here could be a verification link.',
  } }]);
  assert.ok(!`${server.stdout}${server.stderr}`.includes(credentials.password));
  assert.ok(!`${server.stdout}${server.stderr}`.includes(f.key.toString('hex')));
  const restarted = await start(t, f);
  await restarted.post('/api/signup', credentials, 409);
  await restarted.post('/api/login', credentials);
  for (const persistent of [token, external]) {
    assert.equal((await restarted.post('/api/validate', { token: persistent })).valid, true);
  }
  await restarted.stop();
  assert.equal(restarted.stdout, '', 'duplicate signup must not send another email');
});

test('stdout failure preserves the committed account', { skip: process.platform !== 'linux', timeout: 120_000 }, async t => {
  const f = await fixture(t);
  const full = await open('/dev/full', 'w');
  t.after(() => full.close());
  const server = await start(t, f, { stdout: full.fd });
  await server.post('/api/signup', credentials, 500);
  await server.post('/api/signup', credentials, 409);
  const { token } = await server.post('/api/login', credentials);
  assert.equal((await server.post('/api/validate', { token })).valid, true);
  await server.stop();
});

test('approved origin overrides fallback authorities', { timeout: 120_000 }, async t => {
  const f = await fixture(t);
  const server = await start(t, f, { config(value) {
    value.policy.approved_origin = 'https://public.example.test';
    return value;
  } });
  assert.equal((await server.request('/')).status, 403);
  assert.equal((await server.request('/', { headers: { host: 'public.example.test', origin: 'https://public.example.test' } })).status, 200);
  assert.equal((await server.request('/', { headers: { host: 'public.example.test', origin: 'http://public.example.test' } })).status, 403);
});

test('missing or malformed provisioning fails closed', { timeout: 600_000 }, async t => {
  const cases = [
    ['missing key', undefined, null],
    ...[0, 31, 33, 64].map(length => [`key length ${length}`, undefined, randomBytes(length).toString('base64url')]),
    ['invalid base64url key', undefined, '!'.repeat(43)],
    ['standard base64 key', undefined, Buffer.alloc(32, 255).toString('base64')],
    ['raw binary key', undefined, Buffer.alloc(32)],
    ['missing config', () => undefined],
    ['malformed JSON', () => '{'],
    ['unknown field', value => ({ ...value, unexpected: true })],
    ['missing service', value => ({ policy: value.policy })],
    ['empty issuer', value => { value.service.issuer = ''; return value; }],
    ['zero TTL', value => { value.service.token_ttl_seconds = 0; return value; }],
    ['negative TTL', value => { value.service.token_ttl_seconds = -1; return value; }],
    ['invalid sender', value => { value.service.email_from = 'bad\r\nFrom: injected'; return value; }],
    ['empty policy', value => { value.policy.approved_authorities = []; return value; }],
    ['invalid authority', value => { value.policy.approved_authorities = ['user@evil.test']; return value; }],
    ['invalid origin', value => { value.policy.approved_origin = 'https://example.test/path'; return value; }],
  ];
  for (const [name, config, key] of cases) await t.test(name, async t => {
    const f = await fixture(t);
    if (key === null) await rm(join(f.directory, 'config/signing.key'));
    else if (key !== undefined) await writeFile(join(f.directory, 'config/signing.key'), key, { mode: 0o600 });
    const server = await start(t, f, { config });
    // Wasmtime maps a component trap to HTTP 500. A network failure is not
    // accepted: it could hide broken flags, a missing artifact or a dead server.
    for (const [path, body] of [
      ['/api/signup', credentials], ['/api/login', credentials],
      ['/api/validate', { token: sign(f.key, { iss: issuer, sub: 'test', iat: 1, exp: 9999999999 }) }],
    ]) {
      const response = await server.request(path, { method: 'POST',
        headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
      assert.equal(response.status, 500, `${name}: ${response.body}\n${server.diagnostics()}`);
      assert.ok(!response.body.includes(f.key.toString('hex')));
      assert.ok(!response.body.includes(f.key.toString('base64url')));
    }
    assert.deepEqual(await readdir(join(f.directory, 'accounts')), []);
    await server.stop();
    assert.equal(server.stdout, '', 'invalid provisioning must not send mail');
  });
});

test('committed account envelope survives restart and corrupt records fail closed', { timeout: 240_000 }, async t => {
  const f = await fixture(t);
  const accounts = join(f.directory, 'accounts');
  const name = `${createHash('sha256').update(credentials.email).digest('hex')}.account`;
  const path = join(accounts, name);
  const server = await start(t, f);
  await server.post('/api/signup', credentials, 201);
  assert.deepEqual(await readdir(accounts), [name], 'only the committed account remains, not temporary files');
  const committed = await readFile(path);
  assert.equal(committed.subarray(0, 8).toString('ascii'), 'AKSTORE1');
  const keyLength = committed.readUInt32LE(8);
  assert.equal(keyLength, Buffer.byteLength(credentials.email));
  assert.equal(committed.subarray(12, 12 + keyLength).toString('utf8'), credentials.email);
  assert.ok(committed.length > 12 + keyLength, 'the envelope contains an account value');
  await server.stop();

  const restarted = await start(t, f);
  await restarted.post('/api/signup', { ...credentials, password: 'replacement-password' }, 409);
  assert.deepEqual(await readFile(path), committed, 'duplicate signup cannot replace the committed bytes');
  await restarted.post('/api/login', credentials);

  const wrongKey = Buffer.from(committed);
  wrongKey[12] ^= 1;
  for (const [label, corrupt] of [
    ['truncated envelope', Buffer.from('broken')],
    ['mismatched embedded key', wrongKey],
    ['oversized record', Buffer.alloc(1024 * 1024 + 1)],
  ]) {
    await writeFile(path, corrupt);
    await restarted.post('/api/login', credentials, 500);
    await restarted.post('/api/signup', credentials, 500);
    assert.deepEqual(await readFile(path), corrupt, `${label}: signup must not overwrite corruption`);
    assert.deepEqual(await readdir(accounts), [name], `${label}: no new account or temporary files`);
  }
  await restarted.stop();
  assert.equal(restarted.stdout, '', 'duplicates and corrupt accounts must not send mail');
});

test('concurrent signup across processes publishes exactly one immutable account', { timeout: 240_000 }, async t => {
  const first = await fixture(t);
  const second = await fixture(t);
  const accounts = join(first.directory, 'accounts');
  // Each process keeps its own port-specific policy while sharing only storage.
  await rm(join(second.directory, 'accounts'), { recursive: true });
  await symlink(accounts, join(second.directory, 'accounts'), 'dir');
  const servers = [await start(t, first), await start(t, second)];
  const contenders = [
    { email: 'race@example.test', password: 'first-racing-password' },
    { email: 'race@example.test', password: 'second-racing-password' },
  ];
  // Separate processes allow overlap despite serve's per-process concurrency limit.
  const responses = await Promise.all(servers.map((server, index) => server.request('/api/signup', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify(contenders[index]),
  })));
  assert.deepEqual(responses.map(response => response.status).sort((a, b) => a - b), [201, 409],
    responses.map((response, index) => `${response.body}\n${servers[index].diagnostics()}`).join('\n'));
  const winner = responses.findIndex(response => response.status === 201);
  const name = `${createHash('sha256').update(contenders[winner].email).digest('hex')}.account`;
  assert.deepEqual(await readdir(accounts), [name], 'one committed file and no temporary files');
  const committed = await readFile(join(accounts, name));
  for (const server of servers) {
    await server.post('/api/login', contenders[winner]);
    await server.post('/api/login', contenders[1 - winner], 401);
    await server.post('/api/signup', contenders[1 - winner], 409);
  }
  assert.deepEqual(await readFile(join(accounts, name)), committed, 'the losing signup cannot replace the winner');
  assert.deepEqual(await readdir(accounts), [name]);
  await Promise.all(servers.map(server => server.stop()));
  const emails = servers.flatMap(server => server.stdout.trim().split('\n').filter(Boolean).map(line => JSON.parse(line)));
  assert.equal(emails.length, 1, 'only the winning signup sends mail');
  assert.deepEqual(emails[0].email.to, [contenders[winner].email]);
});
