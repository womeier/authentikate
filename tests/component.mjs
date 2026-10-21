// Run after node components/service/build.mjs. Hosts below test ABI/control flow,
// not cryptography; real crypto remains mandatory component imports.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync, existsSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';

const out = resolve(process.argv[2] ?? 'build');
// Verify the actual generated wrapper independently of the extraction compiler.
// The tiny synthetic module models only the documented heap/closure ABI.
{
  const temp = mkdtempSync(resolve(tmpdir(), 'service-wrapper-'));
  try {
    writeFileSync(`${temp}/rocq.wat`, `(module
      (import "test" "request" (func $request (param i32 i32 i32)))
      (import "test" "start" (func $start))
      (memory (export "memory") 1)
      (global $heap (export "mem_ptr") (mut i32) (i32.const 0))
      (global (export "out_of_mem") (mut i32) (i32.const 0))
      (global $result (export "result") (mut i32) (i32.const 0))
      (global $cfg (mut i32) (i32.const 0))
      (global $now (mut i32) (i32.const 0))
      (table (export "table") 3 funcref)
      (elem (i32.const 0) $config $time $body)
      (func (export "main_function")
        (call $start)
        (i32.store (i32.const 20) (i32.const 32))
        (i32.store (i32.const 24) (i32.const 32))
        (i32.store (i32.const 28) (i32.const 32))
        (i32.store (i32.const 68) (i32.const 1))
        (i32.store (i32.const 84) (i32.const 2))
        (global.set $heap (i32.const 256))
        (global.set $result (i32.const 16)))
      (func $config (param i32) (param $value i32)
        (global.set $cfg (local.get $value))
        (global.set $result (i32.const 64)))
      (func $time (param i32) (param $value i32)
        (global.set $now (local.get $value))
        (global.set $result (i32.const 80)))
      (func $body (param i32) (param $value i32)
        (call $request (global.get $cfg) (global.get $now) (local.get $value))
        (global.set $result (i32.const 96))))`);
    execFileSync('wasm-tools', ['parse', `${temp}/rocq.wat`, '-o', `${temp}/rocq.wasm`]);
    let wrapper, starts = 0, calls = 0, clockCalls = 0;
    let clockSeconds = 0xffffffffffffffffn;
    const rocq = new WebAssembly.Instance(new WebAssembly.Module(readFileSync(`${temp}/rocq.wasm`)), {
      test: {
        start() { assert.equal(++starts, 1, 'initialize extraction exactly once'); },
        request(cfg, now, body) {
          calls++;
          const mem = new DataView(rocq.memory.buffer);
          const get = p => mem.getUint32(p, true);
          const N = p => {
            if (p & 1) return 0n;
            function pos(q) { return q & 1 ? 1n : 2n * pos(get(q + 4)) + BigInt(get(q) === 0); }
            return pos(get(p + 4));
          };
          const bytes = p => {
            const result = [];
            while (!(p & 1)) { result.push(get(p + 4) >>> 1); p = get(p + 8); }
            return result;
          };
          assert.equal(N(get(cfg + 4)), 0xffffffffn);
          assert.deepEqual(bytes(get(cfg + 8)), [0, 128, 255]);
          assert.deepEqual(bytes(get(cfg + 12)), [65]);
          assert.equal(N(get(cfg + 16)), 0x100000001n);
          assert.deepEqual(bytes(get(cfg + 20)), [1, 2]);
          assert.deepEqual(bytes(get(cfg + 24)), [254]);
          const costs = get(cfg + 28);
          assert.deepEqual([4, 8, 12, 16, 20].map(i => N(get(costs + i))), [2n, 19456n, 2n, 1n, 32n]);
          assert.deepEqual(bytes(get(cfg + 32)), [70, 0, 128, 255]);
          assert.equal(N(now), clockSeconds);
          assert.deepEqual(bytes(body), [0, 255]);
          // Return a pair whose N status is 1 and whose body reuses the input.
          mem.setUint32(104, body, true);
          mem.setUint32(100, 112, true);
          mem.setUint32(112, 0, true);
          mem.setUint32(116, 1, true);
        },
      },
    }).exports;
    let boundaryArgs, boundaryResidue;
    const adapter = (...args) => {
      assert.ok(boundaryArgs, 'Synthetic closure test must not call adapters');
      assert.deepEqual(args, boundaryArgs, 'FFI boundary must forward every argument, including force');
      rocq.mem_ptr.value = 65532 + boundaryResidue;
      rocq.result.value = 1;
    };
    const service = new WebAssembly.Module(readFileSync(`${out}/service.wasm`));
    assert.deepEqual(WebAssembly.Module.imports(service).map(i => `${i.module}#${i.name}:${i.kind}`).sort(), [
      'rocq#memory:memory', 'rocq#table:table', 'rocq#mem_ptr:global', 'rocq#out_of_mem:global',
      'rocq#result:global', 'rocq#main_function:function',
      'argon2#ffi_argon2_verify:function', 'argon2#ffi_argon2_enroll:function', 'argon2#ffi_secret_of_bytes:function',
      'ed25519#ffi_ed25519_sign:function', 'ed25519#ffi_ed25519_verify:function',
      'store#ffi_kv_get:function', 'store#ffi_kv_set:function', 'email#ffi_email_send:function',
      'wasi:clocks/wall-clock@0.2.0#now:function',
    ].sort());
    wrapper = new WebAssembly.Instance(service, {
      rocq,
      argon2: { ffi_argon2_verify: adapter, ffi_argon2_enroll: adapter, ffi_secret_of_bytes: adapter },
      ed25519: { ffi_ed25519_sign: adapter, ffi_ed25519_verify: adapter },
      store: { ffi_kv_get: adapter, ffi_kv_set: adapter },
      email: { ffi_email_send: adapter },
      'wasi:clocks/wall-clock@0.2.0': {
        now(ret) {
          clockCalls++;
          assert.equal(ret % 8, 0);
          const mem = new DataView(rocq.memory.buffer);
          mem.setBigUint64(ret, clockSeconds, true);
          mem.setUint32(ret + 8, 999999999, true);
        },
      },
    }).exports;
    for (const endpoint of ['login', 'validate', 'signup']) {
      const args = wrapper.cabi_realloc(0, 0, 8, 88);
      assert.equal(args % 8, 0);
      new Uint8Array(rocq.memory.buffer, args, 88).fill(0);
      const put = (p, v) => new DataView(rocq.memory.buffer).setUint32(p, v, true);
      put(args, 0xffffffff);
      for (const [offset, bytes] of [[4, [0, 128, 255]], [12, [65]], [32, [1, 2]], [40, [254]],
        [68, [70, 0, 128, 255]], [80, [0, 255]]]) {
        const p = wrapper.cabi_realloc(0, 0, 1, bytes.length);
        new Uint8Array(rocq.memory.buffer).set(bytes, p);
        put(args + offset, p); put(args + offset + 4, bytes.length);
      }
      new DataView(rocq.memory.buffer).setBigUint64(args + 24, 0x100000001n, true);
      put(args + 76, 0xdeadbeef); // Config tail padding must not become the timestamp.
      [2, 19456, 2, 1, 32].forEach((v, i) => put(args + 48 + 4 * i, v));
      const ret = wrapper[`authentikate:service/api@0.1.0#${endpoint}`](args);
      const mem = new DataView(rocq.memory.buffer);
      assert.equal(mem.getUint32(ret, true), 1);
      assert.deepEqual([...new Uint8Array(rocq.memory.buffer, mem.getUint32(ret + 4, true), mem.getUint32(ret + 8, true))], [0, 255]);
      assert.equal(clockCalls, calls, 'read the clock exactly once per request');
      clockSeconds = clockSeconds === 0xffffffffffffffffn ? 0n : 0x100000001n;
    }
    assert.equal(calls, 3);
    for (const [name, arity] of [['ffi_argon2_verify', 5], ['ffi_argon2_enroll', 2],
      ['ffi_secret_of_bytes', 2], ['ffi_ed25519_sign', 3], ['ffi_ed25519_verify', 4],
      ['ffi_kv_get', 2], ['ffi_kv_set', 3], ['ffi_email_send', 5]]) {
      assert.equal(wrapper[name].length, arity);
      boundaryArgs = Array.from({ length: arity }, (_, i) => i + 10);
      for (boundaryResidue of [1, 2, 3]) {
        assert.equal(wrapper[name](...boundaryArgs), undefined);
        assert.equal(rocq.mem_ptr.value, 65536, `${name} must restore four-byte alignment`);
        assert.equal(rocq.result.value, 1, `${name} must preserve immediate None`);
      }
    }
    console.log('wrapper: all config fields, full u64 clock snapshots, bytes, curried closures, response lowering, initialize-once/reuse');
    console.log('FFI boundaries: all eight preserve arguments/results and align all three nonzero heap residues');
  } finally { rmSync(temp, { recursive: true, force: true }); }
}

if (!existsSync(`${out}/authentikate.component.wasm`)) {
  throw new Error('Component is missing; complete WIT dependencies and rebuild');
}
execFileSync('wasm-tools', ['validate', `${out}/authentikate.component.wasm`], { stdio: 'inherit' });
const wit = execFileSync('wasm-tools', ['component', 'wit', `${out}/authentikate.component.wasm`], { encoding: 'utf8' });
for (const name of ['wasi:keyvalue/store@0.2.0-draft', 'authentikate:crypto/argon2@0.1.0',
  'authentikate:crypto/ed25519@0.1.0', 'authentikate:email/sender@0.1.0',
  'wasi:clocks/wall-clock@0.2.0']) assert.ok(wit.includes(`import ${name}`), name);
assert.deepEqual([...wit.matchAll(/^\s*import ([^;]+);/gm)].map(m => m[1]).sort(), [
  'authentikate:crypto/argon2@0.1.0', 'authentikate:crypto/ed25519@0.1.0',
  'authentikate:email/sender@0.1.0', 'wasi:keyvalue/store@0.2.0-draft',
  'wasi:clocks/wall-clock@0.2.0',
].sort());
assert.ok(wit.includes('export authentikate:service/api@0.1.0'));
for (const endpoint of ['login', 'validate', 'signup']) {
  assert.ok(wit.includes(`${endpoint}: func(config: config, body: list<u8>) -> response;`));
}
assert.ok(!wit.includes('main-function'));
console.log('component: validates; only custom service API exported; exact clock, keyvalue, crypto, and email imports');

const core = new WebAssembly.Module(readFileSync(`${out}/authentikate.core.wasm`));
assert.deepEqual([...new Set(WebAssembly.Module.imports(core).map(i => i.module))].sort(), [
  'authentikate:crypto/argon2@0.1.0', 'authentikate:crypto/ed25519@0.1.0',
  'authentikate:email/sender@0.1.0', 'wasi:keyvalue/store@0.2.0-draft',
  'wasi:clocks/wall-clock@0.2.0',
].sort());
assert.deepEqual(WebAssembly.Module.imports(core).map(i => `${i.module}#${i.name}:${i.kind}`).sort(), [
  'authentikate:crypto/argon2@0.1.0#enroll:function', 'authentikate:crypto/argon2@0.1.0#verify:function',
  'authentikate:crypto/ed25519@0.1.0#sign:function', 'authentikate:crypto/ed25519@0.1.0#verify:function',
  'authentikate:email/sender@0.1.0#send:function', 'wasi:keyvalue/store@0.2.0-draft#open:function',
  'wasi:keyvalue/store@0.2.0-draft#[method]bucket.get:function',
  'wasi:keyvalue/store@0.2.0-draft#[method]bucket.set:function',
  'wasi:clocks/wall-clock@0.2.0#now:function',
].sort());
assert.deepEqual(WebAssembly.Module.exports(core).map(e => e.name).sort(), [
  'authentikate:service/api@0.1.0#login', 'authentikate:service/api@0.1.0#signup',
  'authentikate:service/api@0.1.0#validate', 'cabi_realloc', 'memory',
]);
let e, mode = 'missing', verifyError = false, verifyMatched = false;
let enrollError = false, writeError = false, allowEnrollment = false;
let signError = false, signatureError = false;
let sendError = false, clockSeconds = 0n, clockCalls = 0;
let opens = 0, gets = 0, hashes = 0, enrolls = 0, writes = 0;
const emails = [], events = [];
const store = new Map();
const view = () => new DataView(e.memory.buffer);
const put = (p, n) => view().setUint32(p, n, true);
const get = p => view().getUint32(p, true);
const bytes = (p, n) => Buffer.from(new Uint8Array(e.memory.buffer, p, n));
function flat(data) {
  const p = e.cabi_realloc(0, 0, 1, data.length);
  new Uint8Array(e.memory.buffer).set(data, p);
  return [p, data.length];
}
function list(ret, data, offset = 4) {
  const [p, n] = flat(data);
  put(ret + offset, p); put(ret + offset + 4, n);
}
function failure(ret, variant = 0) {
  put(ret, 1); put(ret + 4, variant); put(ret + 8, 0); put(ret + 12, 0);
}
const imports = {
  'wasi:clocks/wall-clock@0.2.0': {
    now(ret) {
      clockCalls++;
      assert.equal(ret % 8, 0);
      view().setBigUint64(ret, clockSeconds, true);
      put(ret + 8, 999999999);
    },
  },
  'wasi:keyvalue/store@0.2.0-draft': {
    open(p, n, ret) { opens++; assert.equal(n, 0); put(ret, 0); put(ret + 4, 7); },
    '[method]bucket.get'(handle, p, n, ret) {
      gets++; assert.equal(handle, 7);
      if (mode === 'outage') { failure(ret); return; }
      const value = store.get(bytes(p, n).toString());
      put(ret, 0);
      put(ret + 4, Number(Boolean(value)));
      if (value) list(ret, value, 8);
    },
    '[method]bucket.set'(handle, p, n, vp, vn, ret) {
      writes++; assert.equal(handle, 7);
      if (writeError) { failure(ret); return; }
      store.set(bytes(p, n).toString(), bytes(vp, vn));
      events.push('write');
      put(ret, 0);
    },
  },
  'authentikate:crypto/argon2@0.1.0': {
    verify(pp, pn, sp, sn, algorithm, memory, iterations, parallelism, length, tp, tn, ret) {
      hashes++;
      assert.equal(bytes(pp, pn).toString(), 'password');
      assert.deepEqual([algorithm, memory, iterations, parallelism, length], [2, 19456, 2, 1, 32]);
      assert.equal(bytes(sp, sn).toString(), 'salt-salt');
      assert.equal(bytes(tp, tn).length, 32);
      if (verifyError) { failure(ret); return; }
      put(ret, 0); put(ret + 4, Number(verifyMatched));
    },
    enroll(p, n, ret) {
      assert.ok(allowEnrollment, 'enrollment must not run before a parsed signup requires it');
      enrolls++; assert.equal(bytes(p, n).toString(), 'password');
      if (enrollError) { failure(ret); return; }
      put(ret, 0);
      list(ret, Buffer.from(JSON.stringify({
        algorithm: 2, memory_kib: 19456, iterations: 2, parallelism: 1, tag_length: 32,
        salt: Buffer.from('salt-salt').toString('base64url'), tag: Buffer.alloc(32).toString('base64url'),
      })));
    },
  },
  'authentikate:crypto/ed25519@0.1.0': {
    sign(key, p, n, ret) {
      assert.equal(key >>> 0, 0xffffffff);
      const payload = JSON.parse(Buffer.from(bytes(p, n).toString().split('.')[1], 'base64url'));
      assert.equal(payload.sub, 'user@example.test');
      assert.equal(payload.iss, 'issuer');
      assert.equal(payload.iat, 100);
      assert.equal(payload.exp, 100 + 0x100000001);
      if (signError) { failure(ret, 3); return; }
      put(ret, 0); list(ret, Buffer.alloc(64, 7));
    },
    verify(kp, kn, mp, mn, sp, sn, ret) {
      assert.deepEqual(bytes(kp, kn), Buffer.alloc(32));
      assert.deepEqual(bytes(sp, sn), Buffer.alloc(64, 7));
      assert.equal(bytes(mp, mn).toString().split('.').length, 2);
      if (signatureError) { failure(ret, 2); return; }
      put(ret, 0); put(ret + 4, 1);
    },
  },
  'authentikate:email/sender@0.1.0': {
    send(...args) {
      assert.equal(args.length, 12, 'send uses the canonical flat message ABI');
      const [fp, fn, tp, tn, sp, sn, bp, bn, idem, ip, il, ret] = args;
      assert.equal(tp % 4, 0, 'list<string> descriptors must be aligned');
      assert.deepEqual([idem, ip, il], [0, 0, 0]);
      const message = {
        from: bytes(fp, fn).toString(),
        to: Array.from({ length: tn }, (_, i) => bytes(get(tp + 8 * i), get(tp + 8 * i + 4)).toString()),
        subject: bytes(sp, sn).toString(), text: bytes(bp, bn).toString(),
        idempotencyKey: null,
      };
      assert.deepEqual(message, {
        from: 'Authentikate <hello@example.test>', to: ['user@example.test'],
        subject: 'Welcome to Authentikate', text: 'Your Authentikate account has been created.',
        idempotencyKey: null,
      });
      assert.equal(events.at(-1), 'write', 'send must follow a successful account write');
      assert.equal(JSON.parse(store.get(message.to[0])).email, message.to[0], 'account must exist before send');
      events.push('send');
      emails.push(message);
      if (sendError) failure(ret, 2);
      else put(ret, 0);
    },
  },
};
for (const i of WebAssembly.Module.imports(core)) {
  imports[i.module][i.name] ??= () => assert.fail(`Unexpected host call ${i.module}#${i.name}`);
}
e = new WebAssembly.Instance(core, imports).exports;
function request(endpoint, body, now = 0xffffffffffffffffn) {
  clockSeconds = now;
  const beforeClock = clockCalls;
  const args = e.cabi_realloc(0, 0, 8, 88);
  assert.equal(args % 8, 0);
  new Uint8Array(e.memory.buffer, args, 88).fill(0);
  put(args, 0xffffffff);
  for (const [offset, data] of [[4, Buffer.alloc(32)], [12, Buffer.from('issuer')],
    [32, Buffer.from('salt-salt')], [40, Buffer.alloc(32)],
    [68, Buffer.from('Authentikate <hello@example.test>')], [80, Buffer.from(body)]]) {
    const [p, n] = flat(data); put(args + offset, p); put(args + offset + 4, n);
  }
  view().setBigUint64(args + 24, 0x100000001n, true);
  [2, 19456, 2, 1, 32].forEach((v, i) => put(args + 48 + 4 * i, v));
  const beforeEmails = emails.length;
  const ret = e[`authentikate:service/api@0.1.0#${endpoint}`](args);
  assert.equal(clockCalls, beforeClock + 1, 'read the clock exactly once per request');
  if (endpoint !== 'signup') assert.equal(emails.length, beforeEmails, `${endpoint} must never send email`);
  return { status: get(ret), body: JSON.parse(bytes(get(ret + 4), get(ret + 8)).toString()) };
}
for (const endpoint of ['login', 'validate', 'signup']) {
  assert.deepEqual(request(endpoint, '{}'), { status: 400, body: { error: 'bad request' } });
}
assert.equal(gets, 0); assert.equal(hashes, 0);
assert.deepEqual(request('validate', '{"token":"invalid"}'), { status: 200, body: { valid: false } });
const credentials = '{"email":"user@example.test","password":"password"}';
assert.equal(request('login', credentials).status, 401);
assert.equal(hashes, 1);
verifyError = true;
assert.equal(request('login', credentials).status, 401);
mode = 'outage';
assert.equal(request('login', credentials).status, 500);
assert.equal(request('signup', credentials).status, 500);
assert.equal(enrolls, 0);
mode = 'missing'; enrollError = true; allowEnrollment = true;
assert.equal(request('signup', credentials).status, 500);
assert.equal(writes, 0);
enrollError = false; writeError = true;
assert.equal(request('signup', credentials).status, 500);
assert.equal(writes, 1);
assert.equal(emails.length, 0, 'invalid requests, outages, enrollment and write failures must not send email');
writeError = false;
assert.deepEqual(request('signup', credentials), { status: 201, body: {} });
assert.equal(emails.length, 1);
assert.deepEqual(events, ['write', 'send']);
assert.equal(request('signup', credentials).status, 409);
assert.equal(emails.length, 1, 'duplicate signup must not send email');
assert.equal(writes, 2);
assert.equal(JSON.parse(store.get('user@example.test')).email, 'user@example.test');
verifyError = false; verifyMatched = true;
signError = true;
assert.equal(request('login', credentials, 100n).status, 500);
signError = false;
const login = request('login', credentials, 100n);
assert.equal(login.status, 200);
assert.equal(typeof login.body.token, 'string');
const validation = JSON.stringify({ token: login.body.token });
signatureError = true;
assert.deepEqual(request('validate', validation, 100n), { status: 200, body: { valid: false } });
signatureError = false;
assert.equal(request('validate', validation, 100n).body.valid, true);
assert.equal(request('validate', validation, 100n + 0x100000001n).body.valid, false);
assert.equal(request('validate', validation, 101n + 0x100000001n).body.valid, false);
const before = gets;
mode = 'outage';
assert.equal(request('validate', '{"token":"invalid"}').status, 200);
assert.equal(gets, before, 'validate must not consult the store');
assert.equal(opens, 1, 'sequential requests must retain the instance-local bucket handle');
assert.equal(emails.length, 1, 'login and validate must not send email');
mode = 'missing';
store.delete('user@example.test');
events.length = 0;
sendError = true;
assert.deepEqual(request('signup', credentials), { status: 500, body: { error: 'internal error' } });
assert.deepEqual(events, ['write', 'send']);
assert.equal(emails.length, 2);
assert.equal(JSON.parse(store.get('user@example.test')).email, 'user@example.test', 'send failure must not roll back the account');
const beforeRetry = [enrolls, writes, emails.length];
sendError = false;
assert.equal(request('signup', credentials).status, 409);
assert.deepEqual([enrolls, writes, emails.length], beforeRetry, 'retry after send failure must not enroll, write, or send again');
console.log('core: real extracted closures, sequential requests, malformed input, dummy hashing, enrollment, persistence/refusals, validation isolation, post-write welcome email and send failure persistence');
