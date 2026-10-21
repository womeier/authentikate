// Run with node tests/email.mjs. All host capabilities are mocks, never network APIs.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { after, test } from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = new URL('../', import.meta.url);
const output = mkdtempSync(fileURLToPath(new URL('build/email-test-', root)));
writeFileSync(`${output}/package.json`, '{"type":"module"}\n');
after(() => rmSync(output, { recursive: true, force: true }));
const components = {};
const backends = process.argv.includes('--stdout') ? ['stdout'] : ['stdout', 'lettermint'];
for (const backend of backends) {
  const directory = pathToFileURL(`${output}/${backend}/`);
  execFileSync('jco', [
    'transpile', fileURLToPath(new URL(`build/email-${backend}.component.wasm`, root)),
    '-o', fileURLToPath(directory), '--name', 'email', '--instantiation', 'sync',
    '--no-wasi-shim', '--quiet',
  ], { cwd: fileURLToPath(root), stdio: ['ignore', 'ignore', 'inherit'] });
  const { instantiate } = await import(new URL('email.js', directory));
  const modules = new Map();
  components[backend] = imports => instantiate(path => {
    if (!modules.has(path)) {
      modules.set(path, new WebAssembly.Module(readFileSync(new URL(path, directory))));
    }
    return modules.get(path);
  }, imports)['authentikate:email/sender@0.1.0'];
}

function message(overrides = {}) {
  return {
    from: 'Authentikate <hello@example.com>',
    to: ['user@example.com', 'other@example.com'],
    subject: 'Welcome "friend"',
    text: 'Hello\nworld \\ "quoted"',
    idempotencyKey: 'welcome-123',
    ...overrides,
  };
}

function host(backend, settings = {}) {
  const state = { chunks: [], requests: [], stdoutCalls: 0, environmentCalls: 0,
    writes: 0, finished: false, polls: 0, gets: 0 };
  class OutputStream {
    blockingWriteAndFlush(bytes) {
      assert(bytes.length <= 4096, 'WASI blocking writes must not exceed 4096 bytes');
      state.writes++;
      if (settings.outputError) throw { tag: 'closed' };
      if (backend === 'lettermint') assert.equal(state.requests.length, 1, 'dispatch before writing');
      // The lifted bytes alias Wasm memory and must be copied before returning.
      state.chunks.push(Buffer.from(bytes));
    }
  }
  class Pollable {
    block() {
      state.polls++;
      assert.equal(state.polls, 1, 'response should become ready after one poll');
    }
  }
  class Fields {
    static fromList(entries) {
      const fields = new Fields();
      fields.entries = entries.map(([name, value]) => [name, Buffer.from(value).toString('utf8')]);
      return fields;
    }
  }
  class OutgoingBody {
    write() {
      return new OutputStream();
    }
    static finish(body, trailers) {
      assert(body instanceof OutgoingBody);
      assert.equal(trailers, undefined);
      if (settings.finishError) throw { tag: 'HTTP-request-body-size', val: undefined };
      state.finished = true;
    }
  }
  class OutgoingRequest {
    constructor(headers) {
      assert(headers instanceof Fields);
      this.headers = headers;
    }
    body() { return new OutgoingBody(); }
    setMethod(value) { this.method = value; }
    setScheme(value) { this.scheme = value; }
    setAuthority(value) { this.authority = value; }
    setPathWithQuery(value) { this.path = value; }
  }
  class RequestOptions {
    setConnectTimeout(value) {
      if (settings.unsupportedTimeout === 'connect') throw undefined;
      this.connect = value;
    }
    setFirstByteTimeout(value) {
      if (settings.unsupportedTimeout === 'first-byte') throw undefined;
      this.firstByte = value;
    }
    setBetweenBytesTimeout(value) {
      if (settings.unsupportedTimeout === 'between-byte') throw undefined;
      this.betweenBytes = value;
    }
  }
  class IncomingResponse {
    status() { return settings.status ?? 202; }
  }
  class FutureIncomingResponse {
    subscribe() { return new Pollable(); }
    get() {
      assert(state.finished, 'finish request body before awaiting the response');
      state.gets++;
      if (state.gets === 1) return undefined;
      assert.equal(state.gets, 2);
      assert.equal(state.polls, 1);
      if (settings.consumed) return { tag: 'err', val: undefined };
      return { tag: 'ok', val: settings.responseError
        ? { tag: 'err', val: { tag: 'connection-timeout' } }
        : { tag: 'ok', val: new IncomingResponse() } };
    }
  }
  const imports = {
    'wasi:io/error': { Error: class {} },
    'wasi:io/streams': { OutputStream },
    'wasi:io/poll': { Pollable },
    'wasi:clocks/monotonic-clock': {},
    'wasi:cli/stdout': { getStdout() { state.stdoutCalls++; return new OutputStream(); } },
    'wasi:cli/environment': { getEnvironment() {
      state.environmentCalls++;
      return settings.environment ?? [['LETTERMINT_PROJECT_TOKEN', 'test-project-token']];
    } },
    'wasi:http/types': { Fields, OutgoingRequest, OutgoingBody, RequestOptions,
      IncomingResponse, FutureIncomingResponse },
    'wasi:http/outgoing-handler': { handle(request, options) {
      assert(request instanceof OutgoingRequest);
      assert(options instanceof RequestOptions);
      state.requests.push({ request, options });
      if (settings.transportError) throw { tag: 'connection-refused' };
      return new FutureIncomingResponse();
    } },
  };
  return { sender: components[backend](imports), state };
}

function fails(sender, email, tag, value) {
  assert.throws(() => sender.send(email), error => {
    assert.equal(error.payload?.tag, tag);
    if (value !== undefined) assert.equal(error.payload.val, value);
    else assert.equal(typeof error.payload.val, 'string');
    return true;
  });
}

for (const large of [false, true]) {
  test(`stdout JSON round trip${large ? ' over 4096 bytes' : ''}`, () => {
    const email = message(large ? { text: 'large \"body\"\n'.repeat(1200) } : {});
    const { sender, state } = host('stdout');
    assert.equal(sender.send(email), undefined);
    const bytes = Buffer.concat(state.chunks);
    assert.equal(bytes.at(-1), 10);
    assert.equal(bytes.toString().split('\n').length, 2, 'exactly one JSON line');
    const { idempotencyKey, ...payload } = email;
    assert.deepEqual(JSON.parse(bytes), { backend: 'stdout', email: payload, idempotency_key: idempotencyKey });
    if (large) assert(state.chunks.length > 1);
    assert.equal(state.requests.length, 0);
  });
}

test('stdout stream errors map to transport', () => {
  const { sender, state } = host('stdout', { outputError: true });
  fails(sender, message(), 'transport', 'output stream failed');
  assert.equal(state.writes, 1);
  assert.deepEqual(state.chunks, []);
});

for (const large of [false, true]) {
  test(`Lettermint 202 request contract${large ? ' with chunked body' : ''}`, () => {
    const email = message(large ? { text: 'body\n'.repeat(2000) } : {});
    const { sender, state } = host('lettermint');
    assert.equal(sender.send(email), undefined);
    assert.equal(state.requests.length, 1);
    const { request, options } = state.requests[0];
    assert.deepEqual(request.method, { tag: 'post' });
    assert.deepEqual(request.scheme, { tag: 'HTTPS' });
    assert.equal(request.authority, 'api.lettermint.co');
    assert.equal(request.path, '/v1/send');
    assert.deepEqual(Object.fromEntries(request.headers.entries), {
      'content-type': 'application/json', accept: 'application/json',
      'x-lettermint-token': 'test-project-token', 'idempotency-key': email.idempotencyKey,
    });
    assert.equal(request.headers.entries.length, 4);
    assert.deepEqual({ connect: options.connect, firstByte: options.firstByte,
      betweenBytes: options.betweenBytes }, {
      connect: 30_000_000_000n, firstByte: 30_000_000_000n, betweenBytes: 30_000_000_000n,
    });
    const { idempotencyKey, ...payload } = email;
    assert.deepEqual(JSON.parse(Buffer.concat(state.chunks)), payload);
    assert(state.finished);
    assert.equal(state.polls, 1);
    if (large) assert(state.chunks.length > 1);
  });
}

for (const backend of backends) {
  test(`${backend} omits an absent idempotency key`, () => {
    const { sender, state } = host(backend);
    sender.send(message({ idempotencyKey: undefined }));
    const record = JSON.parse(Buffer.concat(state.chunks));
    const payload = backend === 'stdout' ? record.email : record;
    assert(!Object.hasOwn(record, 'idempotency_key'));
    assert(!Object.hasOwn(payload, 'idempotencyKey'));
    if (backend === 'lettermint') {
      assert(!state.requests[0].request.headers.entries.some(([name]) => name === 'idempotency-key'));
    }
  });
}

for (const status of [401, 422, 429, 500, 302]) {
  test(`Lettermint rejects HTTP ${status} without retrying or following redirects`, () => {
    const { sender, state } = host('lettermint', { status });
    fails(sender, message(), 'rejected', status);
    assert.equal(state.requests.length, 1);
    assert(state.finished);
  });
}

for (const [setting, expected] of [
  ['transportError', 'HTTP request failed'],
  ['responseError', 'HTTP request failed'],
  ['consumed', 'HTTP response already consumed'],
  ['outputError', 'output stream failed'],
  ['finishError', 'HTTP request body failed'],
]) {
  test(`Lettermint maps ${setting} to transport`, () => {
    const { sender, state } = host('lettermint', { [setting]: true });
    fails(sender, message(), 'transport', expected);
    assert.equal(state.requests.length, 1);
    if (setting === 'transportError') assert.equal(state.writes, 0);
    if (setting === 'outputError') assert.equal(state.finished, false);
  });
}

for (const timeout of ['connect', 'first-byte', 'between-byte']) {
  test(`Lettermint reports unsupported ${timeout} timeout without sending`, () => {
    const { sender, state } = host('lettermint', { unsupportedTimeout: timeout });
    fails(sender, message(), 'configuration', `${timeout} timeout unsupported`);
    assert.equal(state.requests.length, 0);
  });
}

for (const token of [undefined, '', 'bad\r\ntoken', 'bad token']) {
  test(`Lettermint rejects ${JSON.stringify(token) ?? 'missing'} token before sending`, () => {
    const environment = token === undefined ? [] : [['LETTERMINT_PROJECT_TOKEN', token]];
    const { sender, state } = host('lettermint', { environment });
    fails(sender, message(), 'configuration', 'LETTERMINT_PROJECT_TOKEN is missing or invalid');
    assert.equal(state.environmentCalls, 1);
    assert.equal(state.requests.length, 0);
    assert.equal(state.writes, 0);
  });
}

const invalid = [
  ['empty sender', { from: '' }],
  ['header injection', { from: 'hello@example.com\r\nBcc: other@example.com' }],
  ['no recipients', { to: [] }],
  ['too many recipients', { to: Array(51).fill('user@example.com') }],
  ['invalid recipient', { to: ['user@example.com\n'] }],
  ['blank subject', { subject: ' ' }],
  ['empty body', { text: '' }],
  ['blank body', { text: ' \n\t' }],
  ['invalid idempotency key', { idempotencyKey: 'bad\nkey' }],
  ['empty idempotency key', { idempotencyKey: '' }],
  ['long idempotency key', { idempotencyKey: 'k'.repeat(256) }],
  ['oversize message', { text: 'x'.repeat(1024 * 1024) }],
];
for (const backend of backends) {
  for (const [name, overrides] of invalid) {
    test(`${backend} rejects ${name} without host output`, () => {
      const { sender, state } = host(backend);
      fails(sender, message(overrides), 'invalid-message');
      assert.equal(state.stdoutCalls, 0);
      assert.equal(state.environmentCalls, 0);
      assert.equal(state.requests.length, 0);
      assert.equal(state.writes, 0);
    });
  }
}
