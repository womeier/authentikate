// Run with node tests/email-smtp.mjs after building the SMTP component. No live I/O.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { after, test } from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = new URL('../', import.meta.url);
const output = mkdtempSync(fileURLToPath(new URL('build/email-smtp-test-', root)));
writeFileSync(`${output}/package.json`, '{"type":"module"}\n');
after(() => rmSync(output, { recursive: true, force: true }));
const directory = pathToFileURL(`${output}/`);
execFileSync('jco', [
  'transpile', fileURLToPath(new URL('build/email-smtp.component.wasm', root)),
  '-o', fileURLToPath(directory), '--name', 'email', '--instantiation', 'sync',
  '--no-wasi-shim', '--quiet',
], { cwd: fileURLToPath(root), stdio: ['ignore', 'ignore', 'inherit'] });
const { instantiate } = await import(new URL('email.js', directory));
const modules = new Map();
const transport = 'SMTP transport or protocol failure';
const commands = [
  'EHLO authentikate.local\r\n',
  'MAIL FROM:<hello@example.test>\r\n',
  'RCPT TO:<first@example.test>\r\n',
  'RCPT TO:<second@example.test>\r\n',
  'DATA\r\n',
];
const replies = ['220 ready\r\n', '250 hello\r\n', '250 sender\r\n',
  '250 recipient\r\n', '251 forward\r\n', '354 go ahead\r\n', '250 accepted\r\n'];

function message(overrides = {}) {
  return {
    from: 'Authentikate <hello@example.test>',
    to: ['first@example.test', 'second@example.test'],
    subject: 'Welcome "friend"',
    text: 'Hello\nworld',
    idempotencyKey: 'private-idempotency-key',
    ...overrides,
  };
}

function host(settings = {}) {
  const state = {
    network: 0, sockets: 0, starts: 0, finishes: 0, reads: 0, checks: 0,
    writes: [], frames: [], polls: [], timers: [], now: 123n,
  };
  const responses = settings.replies ?? replies;
  const queue = [Buffer.from(responses[0])];
  let buffered = [], permit = 0n, flushing = false;
  let blocked = Boolean(settings.backpressure), inputWait = Boolean(settings.inputWait);
  let connected = false, accepted = false;
  // Faults are indexed by flushed frame: 0 is EHLO, 5 is the MIME DATA, 6 is QUIT.
  function fault(operation) {
    if ((settings.fault === operation && state.frames.length === (settings.frame ?? 0))
        || (accepted && settings.quitFault === operation)) {
      if (operation === 'create' || operation === 'start' || operation === 'finish') {
        throw 'connection-refused';
      }
      throw { tag: settings.streamError ?? 'closed', val: new IoError() };
    }
  }
  class IoError {
    toDebugString() { throw new Error('server diagnostics must never be exposed'); }
  }
  class Pollable {
    constructor(kind) { this.kind = kind; }
  }
  class Network {}
  const network = new Network();
  class InputStream {
    read(len) {
      assert(connected);
      assert(!flushing, 'read must wait for flush completion');
      assert.equal(buffered.length, 0, 'read must follow a flushed command');
      assert.equal(len, 512n);
      state.reads++;
      assert(state.reads < 100000, 'unbounded input retry');
      fault('read');
      if (inputWait) {
        inputWait = false;
        return new Uint8Array();
      }
      if (!queue.length) throw { tag: 'closed' };
      const chunk = queue[0];
      const count = Math.min(chunk.length, Number(len), settings.fragment ?? 512);
      const bytes = chunk.subarray(0, count);
      if (count === chunk.length) queue.shift();
      else queue[0] = chunk.subarray(count);
      if (state.frames.length === 6 && queue.length === 0) accepted = true;
      return bytes;
    }
    subscribe() { return new Pollable('input'); }
  }
  class OutputStream {
    checkWrite() {
      state.checks++;
      assert(state.checks < 100000, 'unbounded output retry');
      fault('check');
      if (flushing || blocked) return 0n;
      permit = BigInt(settings.permit ?? 65536);
      if (accepted && settings.quitPermit !== undefined) {
        permit = BigInt(settings.quitPermit);
      }
      return permit;
    }
    write(bytes) {
      assert(!flushing && !blocked);
      assert(bytes.length > 0 && bytes.length <= 4096);
      assert(BigInt(bytes.length) <= permit, 'write exceeded check-write permit');
      fault('write');
      // Lifted bytes alias Wasm memory; retain copies, not views.
      const copy = Buffer.from(bytes);
      state.writes.push(copy);
      buffered.push(copy);
      permit = 0n;
      blocked = Boolean(settings.backpressure);
    }
    flush() {
      fault('flush');
      assert(!flushing, 'flush already in progress');
      const frame = Buffer.concat(buffered).toString();
      assert(frame.length > 0, 'empty or duplicate flush');
      state.frames.push(frame);
      buffered = [];
      flushing = Boolean(settings.flushWait);
      if (!flushing) releaseReply();
    }
    subscribe() { return new Pollable('output'); }
  }
  function releaseReply() {
    const response = responses[state.frames.length];
    if (response !== undefined) queue.push(Buffer.from(response));
  }
  class TcpSocket {
    startConnect(actualNetwork, address) {
      state.starts++;
      assert.equal(state.starts, 1, 'must not reconnect or resend');
      assert.equal(actualNetwork, network);
      assert.deepEqual(address, { tag: 'ipv4', val: { port: 25, address: [127, 0, 0, 1] } });
      fault('start');
    }
    finishConnect() {
      state.finishes++;
      assert(state.finishes < 100, 'unbounded connect retry');
      fault('finish');
      if (state.finishes <= (settings.wouldBlock ?? 0)) throw 'would-block';
      connected = true;
      return [new InputStream(), new OutputStream()];
    }
    subscribe() { return new Pollable('socket'); }
  }
  const imports = {
    'wasi:io/error': { Error: IoError },
    'wasi:io/streams': { InputStream, OutputStream },
    'wasi:io/poll': {
      Pollable,
      poll(items) {
        assert.equal(items.length, 2, 'every wait must include the deadline');
        assert(items[0] instanceof Pollable);
        assert.equal(items[1].kind, 'timer');
        state.polls.push(items[0].kind);
        assert(state.polls.length < 100000, 'unbounded polling');
        if (settings.expireOn === items[0].kind) {
          state.now = state.timers[0];
          return new Uint32Array([1]);
        }
        if (items[0].kind === 'output') {
          blocked = false;
          if (flushing) { flushing = false; releaseReply(); }
        }
        return new Uint32Array([0]);
      },
    },
    'wasi:clocks/monotonic-clock': {
      now() {
        const now = state.now;
        state.now += settings.clockStep ?? 0n;
        return now;
      },
      subscribeInstant(when) { state.timers.push(when); return new Pollable('timer'); },
    },
    'wasi:sockets/network': { Network },
    'wasi:sockets/instance-network': { instanceNetwork() { state.network++; return network; } },
    'wasi:sockets/tcp': { TcpSocket },
    'wasi:sockets/tcp-create-socket': {
      createTcpSocket(family) {
        state.sockets++;
        assert.equal(family, 'ipv4');
        fault('create');
        return new TcpSocket();
      },
    },
  };
  const sender = instantiate(path => {
    if (!modules.has(path)) {
      modules.set(path, new WebAssembly.Module(readFileSync(new URL(path, directory))));
    }
    return modules.get(path);
  }, imports)['authentikate:email/sender@0.1.0'];
  return { sender, state };
}

function fails(sender, email, tag = 'transport', value = tag === 'transport' ? transport : undefined) {
  assert.throws(() => sender.send(email), error => {
    assert.equal(error.payload?.tag, tag);
    if (value !== undefined) assert.equal(error.payload.val, value);
    else assert.equal(typeof error.payload.val, 'string');
    return true;
  });
}

function dialogue(state, quit = true) {
  assert.deepEqual(state.frames.slice(0, 5), commands);
  assert(state.frames[5].startsWith('From:'));
  assert(state.frames[5].endsWith('\r\n.\r\n'));
  assert.deepEqual(state.frames.slice(6), quit ? ['QUIT\r\n'] : []);
  assert.equal(state.network, 1);
  assert.equal(state.sockets, 1);
  assert.equal(state.starts, 1);
  assert.deepEqual(state.timers, [30_000_000_123n]);
  const wire = Buffer.concat(state.writes).toString();
  assert(!/AUTH|STARTTLS|RSET|private-idempotency-key/.test(wire));
}

test('SMTP dialogue, envelope order, 251 recipient and final acceptance without QUIT reply', () => {
  const { sender, state } = host();
  assert.equal(sender.send(message()), undefined);
  dialogue(state);
  assert.equal(state.finishes, 1);
  assert.deepEqual(state.polls, []);
});

test('multiline replies survive single-byte reads including split CRLF', () => {
  const { sender, state } = host({ fragment: 1, inputWait: true, replies: [
    '220-first line\r\n220 ready\r\n',
    '250-localhost\r\n250-AUTH PLAIN LOGIN\r\n250 SIZE 1048576\r\n',
    '250\r\n', '250 \r\n', '251\r\n', '354\r\n', '250-queued\r\n250 done\r\n',
  ] });
  sender.send(message());
  dialogue(state);
  assert.deepEqual(state.polls, ['input']);
});

test('partial permitted writes, backpressure, asynchronous flush and WouldBlock connect', () => {
  const email = message({ text: 'long body\n'.repeat(1000) });
  const baseline = host();
  baseline.sender.send(email);
  const { sender, state } = host({ permit: 7, backpressure: true, flushWait: true, wouldBlock: 3 });
  sender.send(email);
  dialogue(state);
  assert.deepEqual(state.frames, baseline.state.frames);
  assert.equal(state.finishes, 4);
  assert.deepEqual(state.polls.slice(0, 3), ['socket', 'socket', 'socket']);
  assert(state.polls.filter(kind => kind === 'output').length > 100);
  assert(state.writes.every(bytes => bytes.length <= 7));
  assert(baseline.state.writes.some(bytes => bytes.length === 4096));
});

for (const [kind, settings] of [
  ['socket', { wouldBlock: 2 }],
  ['input', { inputWait: true }],
  ['output', { backpressure: true }],
  ['flush', { flushWait: true, expireOn: 'output' }],
]) {
  test(`deadline interrupts ${kind} polling without retrying delivery`, () => {
    const { sender, state } = host({ expireOn: kind, ...settings });
    fails(sender, message(), 'transport', 'SMTP deadline exceeded');
    assert.equal(state.polls.length, 1);
    assert.equal(state.starts, 1);
    assert(state.frames.length <= 1);
  });
}

test('deadline also expires during continuously ready I/O', () => {
  const { sender, state } = host({ clockStep: 1_000_000_000n, fragment: 1 });
  fails(sender, message(), 'transport', 'SMTP deadline exceeded');
  assert.deepEqual(state.polls, []);
  assert.equal(state.starts, 1);
  assert(state.frames.length < 5);
});

for (const [stage, index] of [
  ['greeting', 0], ['EHLO', 1], ['MAIL FROM', 2], ['first RCPT', 3],
  ['second RCPT', 4], ['DATA', 5], ['post-DATA', 6],
]) {
  for (const code of [421, 450, 550, 599]) {
    test(`${stage} rejection ${code} is sanitized and never retried`, () => {
      const responses = [...replies];
      responses[index] = `${code} secret-password bearer-token private-idempotency-key\r\n`;
      const { sender, state } = host({ replies: responses });
      fails(sender, message(), 'rejected', code);
      assert.equal(state.frames.length, index);
      assert.deepEqual(state.frames.slice(0, Math.min(index, 5)), commands.slice(0, Math.min(index, 5)));
      assert.equal(state.starts, 1);
      assert.equal(state.sockets, 1);
      assert(!state.frames.includes('QUIT\r\n'));
    });
  }
}

const malformed = [
  ['empty close', ''], ['incomplete', '220 incomplete'], ['bare LF', '220 ready\n'],
  ['bad CRLF', '220 ready\rX\n'], ['short code', '22 ready\r\n'],
  ['nondigit', '2x0 ready\r\n'], ['invalid class low', '120 ready\r\n'],
  ['invalid class high', '620 ready\r\n'], ['invalid separator', '220!ready\r\n'],
  ['NUL', '220 secret\0password\r\n'], ['DEL', '220 secret\x7fpassword\r\n'],
  ['non-ASCII', '220 secret\u00e9password\r\n'],
  ['inconsistent multiline', '220-first\r\n250 last\r\n'],
  ['multiline rejection mismatch', '220-first\r\n550 secret\r\n'],
  ['unfinished multiline', '220-first\r\n'], ['blank line', '\r\n'],
  ['oversize line', `220 ${'x'.repeat(507)}\r\n`],
  ['unterminated oversize line', 'x'.repeat(513)],
  ['too many lines', `${'220-\r\n'.repeat(64)}220 done\r\n`],
  ['too many bytes', `${`220-${'x'.repeat(506)}\r\n`.repeat(32)}220 done\r\n`],
];
for (const [name, response] of malformed) {
  test(`malformed reply: ${name}`, () => {
    const { sender, state } = host({ replies: [response], fragment: 13 });
    fails(sender, message());
    assert.deepEqual(state.frames, []);
    assert.equal(state.starts, 1);
  });
}

test('maximum line, multiline count and aggregate reply sizes are accepted', () => {
  for (const response of [
    `220 ${'x'.repeat(506)}\r\n`,
    `${'220-\r\n'.repeat(63)}220 done\r\n`,
    `${`220-${'x'.repeat(506)}\r\n`.repeat(31)}220 ${'x'.repeat(506)}\r\n`,
  ]) {
    const { sender, state } = host({ replies: [response, ...replies.slice(1)] });
    sender.send(message());
    dialogue(state);
  }
});

test('unexpected positive or intermediate codes are protocol failures, not rejections', () => {
  for (let index = 0; index < replies.length; index++) {
    const responses = [...replies];
    responses[index] = `${index === 5 ? 250 : 354} unexpected secret\r\n`;
    const { sender, state } = host({ replies: responses });
    fails(sender, message());
    assert.equal(state.frames.length, index);
  }
});

for (const operation of ['create', 'start', 'finish', 'read', 'check', 'write', 'flush']) {
  test(`${operation} network failure becomes a sanitized transport error`, () => {
    const { sender, state } = host({ fault: operation });
    fails(sender, message());
    assert.equal(state.sockets, 1);
    assert.equal(state.starts, operation === 'create' ? 0 : 1);
    assert.deepEqual(state.frames, []);
  });
}

for (const frame of [1, 3, 5, 6]) {
  test(`premature close after ${frame} flushed commands is never retried`, () => {
    const { sender, state } = host({ replies: replies.slice(0, frame) });
    fails(sender, message());
    assert.equal(state.frames.length, frame);
    assert.equal(state.starts, 1);
  });
}

test('last-operation-failed stream resources do not leak diagnostics', () => {
  for (const fault of ['read', 'check', 'write', 'flush']) {
    const { sender } = host({ fault, streamError: 'last-operation-failed' });
    fails(sender, message());
  }
});

test('post-DATA stream failures report uncertainty without resending', () => {
  for (const fault of ['read', 'check', 'write', 'flush']) {
    const frame = fault === 'read' ? 6 : 5;
    const { sender, state } = host({ fault, frame });
    fails(sender, message());
    assert.equal(state.frames.length, frame);
    assert.equal(state.starts, 1);
  }
});

test('QUIT errors and insufficient permits cannot change accepted success', () => {
  for (const settings of [
    { quitFault: 'check' }, { quitFault: 'write' },
    { quitFault: 'flush' }, { quitPermit: 0 }, { quitPermit: 5 },
  ]) {
    const { sender, state } = host(settings);
    assert.equal(sender.send(message()), undefined);
    dialogue(state, false);
  }
});

const invalid = [
  { from: '' }, { from: 'a@example.test\r\nBcc: stolen@example.test' },
  { from: 'Name, Other <a@example.test>' }, { from: ' Name <a@example.test>' },
  { from: 'Name <a@example.test> SIZE=1' }, { from: 'Name <a@example.test>>' },
  { from: 'N\u00e4me <a@example.test>' }, { from: 'a..b@example.test' },
  { from: `a@${'x'.repeat(64)}.test` }, { from: `${'x'.repeat(65)}@example.test` },
  { to: [] }, { to: Array(51).fill('a@example.test') },
  ...['Other <a@example.test>', 'a@example.test\nRCPT TO:<x@y>', 'a@example.test SIZE=1',
    'a@@example.test', 'a@-example.test', 'a@example-.test', 'a@exam_ple.test',
    'a@[127.0.0.1]', 'a,b@example.test', 'a@ex\u00e4mple.test', '.a@example.test',
    'a.@example.test', 'a@example..test', 'a@example.test.', 'a@example.test\0',
  ].map(address => ({ to: ['first@example.test', address] })),
  { subject: '' }, { subject: ' ' }, { subject: 'hello\r\nBcc: stolen@example.test' },
  { subject: 'hello\tthere' }, { text: '' }, { text: ' \n\t' },
  ...['', 'has space', 'secret\r\nheader', '\u00e9', 'x'.repeat(256)]
    .map(idempotencyKey => ({ idempotencyKey })),
  { text: 'x'.repeat(1024 * 1024) },
];
test('all shared and SMTP-specific validation happens before any host capability', () => {
  for (const overrides of invalid) {
    const { sender, state } = host();
    fails(sender, message(overrides), 'invalid-message', undefined);
    assert.equal(state.network, 0);
    assert.equal(state.sockets, 0);
    assert.deepEqual(state.timers, []);
    assert.equal(state.now, 123n);
    assert.deepEqual(state.writes, []);
  }
});

test('UTF-8 MIME headers and normalized base64 body round trip without injection', () => {
  const email = message({
    from: `${'Name '.repeat(30).trim()} <hello@example.test>`,
    subject: `${'a'.repeat(44)}${'\u{1f642}\u00e9\u4e2d'.repeat(50)}`,
    text: '\u00e9\r\n.\r\n..\nQUIT\r\n\r\n\0end\rlast\n'.repeat(100),
  });
  const { sender, state } = host();
  sender.send(email);
  dialogue(state);
  const mime = state.frames[5];
  assert(!/[^\x00-\x7f]/.test(mime), 'wire must be seven-bit');
  assert(!/[\r\n]/.test(mime.replaceAll('\r\n', '')), 'only CRLF line endings');
  assert(mime.split('\r\n').every(line => line.length <= 998));
  const [headers, body] = mime.split('\r\n\r\n');
  assert.equal(mime.split('\r\n\r\n').length, 2);
  assert(headers.includes('To:\r\n <first@example.test>,\r\n <second@example.test>'));
  assert(headers.includes('MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: base64'));
  const unfolded = headers.replaceAll('\r\n ', ' ');
  const decodeWords = value => [...value.matchAll(/=\?UTF-8\?B\?([A-Za-z0-9+/=]+)\?=/g)]
    .map(([word, encoded]) => {
      assert(word.length <= 75);
      const bytes = Buffer.from(encoded, 'base64');
      assert.equal(bytes.toString('base64'), encoded);
      return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    }).join('');
  assert.equal(decodeWords(unfolded.match(/^From:(.*)$/m)[1]), email.from.split(' <')[0]);
  assert.equal(decodeWords(unfolded.match(/^Subject:(.*)$/m)[1]), email.subject);
  assert(body.endsWith('\r\n.\r\n'));
  const encodedLines = body.slice(0, -3).split('\r\n');
  assert(encodedLines.every(line => line.length <= 76 && /^[A-Za-z0-9+/=]*$/.test(line)));
  const encoded = encodedLines.join('');
  const bytes = Buffer.from(encoded, 'base64');
  assert.equal(bytes.toString('base64'), encoded);
  assert.equal(bytes.toString(), email.text.replace(/\r\n|\r|\n/g, '\r\n'));
  assert.equal(mime.split('\r\n.\r\n').length, 2, 'exactly one DATA terminator');
  assert(!mime.includes(email.idempotencyKey));
  assert(!/^Bcc:|^Authorization:|^Idempotency-Key:/im.test(headers));
});

test('simple sender, absent idempotency key and base64 padding variants', () => {
  for (const text of ['f', 'fo', 'foo', 'foob', 'fooba', 'foobar']) {
    const { sender, state } = host();
    sender.send(message({ from: 'hello@example.test', idempotencyKey: undefined, text }));
    dialogue(state);
    assert(state.frames[5].startsWith('From: <hello@example.test>\r\n'));
    assert.equal(state.frames[5].split('\r\n\r\n')[1], `${Buffer.from(text).toString('base64')}\r\n.\r\n`);
  }
});
