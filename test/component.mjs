// Run after node tools/build-component.mjs. Hosts below test ABI/control flow,
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
    let wrapper, starts = 0, calls = 0;
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
          assert.equal(N(now), 0xffffffffffffffffn);
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
    wrapper = new WebAssembly.Instance(new WebAssembly.Module(readFileSync(`${out}/service.wasm`)), {
      rocq,
      argon2: { ffi_argon2_verify: adapter, ffi_argon2_enroll: adapter, ffi_secret_of_bytes: adapter },
      ed25519: { ffi_ed25519_sign: adapter, ffi_ed25519_verify: adapter },
      store: { ffi_kv_get: adapter, ffi_kv_set: adapter },
    }).exports;
    for (const endpoint of ['login', 'validate', 'signup']) {
      const args = wrapper.cabi_realloc(0, 0, 8, 88);
      const put = (p, v) => new DataView(rocq.memory.buffer).setUint32(p, v, true);
      put(args, 0xffffffff);
      for (const [offset, bytes] of [[4, [0, 128, 255]], [12, [65]], [32, [1, 2]], [40, [254]], [80, [0, 255]]]) {
        const p = wrapper.cabi_realloc(0, 0, 1, bytes.length);
        new Uint8Array(rocq.memory.buffer).set(bytes, p);
        put(args + offset, p); put(args + offset + 4, bytes.length);
      }
      new DataView(rocq.memory.buffer).setBigUint64(args + 24, 0x100000001n, true);
      new DataView(rocq.memory.buffer).setBigUint64(args + 72, 0xffffffffffffffffn, true);
      [2, 19456, 2, 1, 32].forEach((v, i) => put(args + 48 + 4 * i, v));
      const ret = wrapper[`authentikate:service/api@0.1.0#${endpoint}`](args);
      const mem = new DataView(rocq.memory.buffer);
      assert.equal(mem.getUint32(ret, true), 1);
      assert.deepEqual([...new Uint8Array(rocq.memory.buffer, mem.getUint32(ret + 4, true), mem.getUint32(ret + 8, true))], [0, 255]);
    }
    assert.equal(calls, 3);
    for (const [name, arity] of [['ffi_argon2_verify', 5], ['ffi_argon2_enroll', 2],
      ['ffi_secret_of_bytes', 2], ['ffi_ed25519_sign', 3], ['ffi_ed25519_verify', 4],
      ['ffi_kv_get', 2], ['ffi_kv_set', 3]]) {
      boundaryArgs = Array.from({ length: arity }, (_, i) => i + 10);
      for (boundaryResidue of [1, 2, 3]) {
        assert.equal(wrapper[name](...boundaryArgs), undefined);
        assert.equal(rocq.mem_ptr.value, 65536, `${name} must restore four-byte alignment`);
        assert.equal(rocq.result.value, 1, `${name} must preserve immediate None`);
      }
    }
    console.log('wrapper: all config fields, full u64 values, bytes, curried closures, response lowering, initialize-once/reuse');
    console.log('FFI boundaries: all seven preserve arguments/results and align all three nonzero heap residues');
  } finally { rmSync(temp, { recursive: true, force: true }); }
}

if (!existsSync(`${out}/authentikate.component.wasm`)) {
  throw new Error('Component is missing; complete WIT dependencies and rebuild');
}
execFileSync('wasm-tools', ['validate', `${out}/authentikate.component.wasm`], { stdio: 'inherit' });
const wit = execFileSync('wasm-tools', ['component', 'wit', `${out}/authentikate.component.wasm`], { encoding: 'utf8' });
for (const name of ['wasi:keyvalue/store@0.2.0-draft', 'authentikate:crypto/argon2@0.1.0',
  'authentikate:crypto/ed25519@0.1.0']) assert.ok(wit.includes(`import ${name}`), name);
assert.ok(wit.includes('export authentikate:service/api@0.1.0'));
for (const endpoint of ['login', 'validate', 'signup']) assert.ok(wit.includes(`${endpoint}: func(`));
assert.ok(!wit.includes('main-function'));
console.log('component: validates; only custom service API exported; keyvalue and real crypto interfaces imported');

const core = new WebAssembly.Module(readFileSync(`${out}/authentikate.core.wasm`));
assert.deepEqual([...new Set(WebAssembly.Module.imports(core).map(i => i.module))].sort(), [
  'authentikate:crypto/argon2@0.1.0', 'authentikate:crypto/ed25519@0.1.0',
  'wasi:keyvalue/store@0.2.0-draft',
]);
assert.deepEqual(WebAssembly.Module.exports(core).map(e => e.name).sort(), [
  'authentikate:service/api@0.1.0#login', 'authentikate:service/api@0.1.0#signup',
  'authentikate:service/api@0.1.0#validate', 'cabi_realloc', 'memory',
]);
let e, mode = 'missing', verifyError = false, verifyMatched = false;
let enrollError = false, writeError = false, allowEnrollment = false;
let signError = false, signatureError = false;
let opens = 0, gets = 0, hashes = 0, enrolls = 0, writes = 0;
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
};
for (const i of WebAssembly.Module.imports(core)) {
  imports[i.module][i.name] ??= () => assert.fail(`Unexpected host call ${i.module}#${i.name}`);
}
e = new WebAssembly.Instance(core, imports).exports;
function request(endpoint, body, now = 0xffffffffffffffffn) {
  const args = e.cabi_realloc(0, 0, 8, 88);
  new Uint8Array(e.memory.buffer, args, 88).fill(0);
  put(args, 0xffffffff);
  for (const [offset, data] of [[4, Buffer.alloc(32)], [12, Buffer.from('issuer')],
    [32, Buffer.from('salt-salt')], [40, Buffer.alloc(32)], [80, Buffer.from(body)]]) {
    const [p, n] = flat(data); put(args + offset, p); put(args + offset + 4, n);
  }
  view().setBigUint64(args + 24, 0x100000001n, true);
  view().setBigUint64(args + 72, now, true);
  [2, 19456, 2, 1, 32].forEach((v, i) => put(args + 48 + 4 * i, v));
  const ret = e[`authentikate:service/api@0.1.0#${endpoint}`](args);
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
writeError = false;
assert.deepEqual(request('signup', credentials), { status: 201, body: {} });
assert.equal(request('signup', credentials).status, 409);
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
assert.equal(request('validate', validation, 101n + 0x100000001n).body.valid, false);
const before = gets;
mode = 'outage';
assert.equal(request('validate', '{"token":"invalid"}').status, 200);
assert.equal(gets, before, 'validate must not consult the store');
assert.equal(opens, 1, 'sequential requests must retain the instance-local bucket handle');
console.log('core: real extracted closures, sequential requests, malformed input, dummy hashing, enrollment, persistence/refusals, validation isolation');
