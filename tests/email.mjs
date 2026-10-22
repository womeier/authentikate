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
const directory = pathToFileURL(`${output}/`);
execFileSync('jco', [
  'transpile', fileURLToPath(new URL('build/email-stdout.component.wasm', root)),
  '-o', fileURLToPath(directory), '--name', 'email', '--instantiation', 'sync',
  '--no-wasi-shim', '--quiet',
], { cwd: fileURLToPath(root), stdio: ['ignore', 'ignore', 'inherit'] });
const { instantiate } = await import(new URL('email.js', directory));
const modules = new Map();

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

function host(settings = {}) {
  const state = { chunks: [], stdoutCalls: 0, writes: 0 };
  class OutputStream {
    blockingWriteAndFlush(bytes) {
      assert(bytes.length <= 4096, 'WASI blocking writes must not exceed 4096 bytes');
      state.writes++;
      if (settings.outputError) throw { tag: 'closed' };
      // The lifted bytes alias Wasm memory and must be copied before returning.
      state.chunks.push(Buffer.from(bytes));
    }
  }
  const imports = {
    'wasi:io/error': { Error: class {} },
    'wasi:io/streams': { OutputStream },
    'wasi:cli/stdout': { getStdout() { state.stdoutCalls++; return new OutputStream(); } },
  };
  const sender = instantiate(path => {
    if (!modules.has(path)) {
      modules.set(path, new WebAssembly.Module(readFileSync(new URL(path, directory))));
    }
    return modules.get(path);
  }, imports)['authentikate:email/sender@0.1.0'];
  return { sender, state };
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
    const email = message(large ? { text: 'large "body"\n'.repeat(1200) } : {});
    const { sender, state } = host();
    assert.equal(sender.send(email), undefined);
    const bytes = Buffer.concat(state.chunks);
    assert.equal(bytes.at(-1), 10);
    assert.equal(bytes.toString().split('\n').length, 2, 'exactly one JSON line');
    const { idempotencyKey, ...payload } = email;
    assert.deepEqual(JSON.parse(bytes), { backend: 'stdout', email: payload, idempotency_key: idempotencyKey });
    if (large) assert(state.chunks.length > 1);
  });
}

test('stdout stream errors map to transport', () => {
  const { sender, state } = host({ outputError: true });
  fails(sender, message(), 'transport', 'output stream failed');
  assert.equal(state.writes, 1);
  assert.deepEqual(state.chunks, []);
});

test('stdout omits an absent idempotency key', () => {
  const { sender, state } = host();
  sender.send(message({ idempotencyKey: undefined }));
  const record = JSON.parse(Buffer.concat(state.chunks));
  assert(!Object.hasOwn(record, 'idempotency_key'));
  assert(!Object.hasOwn(record.email, 'idempotencyKey'));
});

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
for (const [name, overrides] of invalid) {
  test(`stdout rejects ${name} without host output`, () => {
    const { sender, state } = host();
    fails(sender, message(overrides), 'invalid-message');
    assert.equal(state.stdoutCalls, 0);
    assert.equal(state.writes, 0);
  });
}
