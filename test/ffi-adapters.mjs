// Run: nix develop --command node test/ffi-adapters.mjs
// Exercise the actual exports without rewriting WAT or exporting internals.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const temp = mkdtempSync(join(tmpdir(), 'ffi-adapters-'));

function heap() {
  const memory = new WebAssembly.Memory({ initial: 1 });
  const global = value => new WebAssembly.Global({ value: 'i32', mutable: true }, value);
  const rocq = { memory, mem_ptr: global(1024), out_of_mem: global(0), result: global(-1) };
  const view = () => new DataView(memory.buffer);
  const put = (p, n) => view().setUint32(p, n, true);
  const get = p => view().getUint32(p, true);
  function alloc(n) {
    const p = (rocq.mem_ptr.value + 3) & ~3;
    const end = p + n;
    if (end > memory.buffer.byteLength) memory.grow(Math.ceil((end - memory.buffer.byteLength) / 65536));
    rocq.mem_ptr.value = end;
    return p;
  }
  function block(...fields) {
    const p = alloc(4 * fields.length);
    fields.forEach((f, i) => put(p + 4 * i, f));
    return p;
  }
  function bytes(data) {
    let tail = 1;
    for (const b of [...data].reverse()) tail = block(0, 2 * b + 1, tail);
    return tail;
  }
  function unbytes(p) {
    const data = [];
    while (!(p & 1)) {
      assert.equal(get(p) & 255, 0);
      data.push(get(p + 4) >>> 1);
      p = get(p + 8);
    }
    assert.equal(p, 1);
    return data;
  }
  function positive(n) {
    if (n === 1n) return 1;
    return block(Number((n & 1n) === 0n), positive(n >> 1n));
  }
  const N = n => BigInt(n) === 0n ? 1 : block(0, positive(BigInt(n)));
  const flat = (p, n) => [...new Uint8Array(memory.buffer, p, n)];
  const some = p => {
    assert.equal(p & 3, 0, 'expected Some, not None');
    assert.equal(get(p) & 255, 0);
    return get(p + 4);
  };
  const call = (fn, ...args) => {
    rocq.result.value = -1;
    // CertiRocq 6d34b50b adds a force dummy before the actual Rocq arguments.
    assert.equal(fn.length, args.length + 1, 'registered FFI must accept force dummy');
    assert.equal(fn(1, ...args), undefined, 'registered FFI must return void');
    assert.notEqual(rocq.result.value, -1, 'registered FFI must set result');
    assert.equal(rocq.out_of_mem.value, 0);
    return rocq.result.value;
  };
  return { rocq, put, get, alloc, block, bytes, unbytes, N, flat, some, call };
}

function instantiate(path, h, imports) {
  const binary = join(temp, path.replaceAll('/', '-') + '.wasm');
  execFileSync('wasm-tools', ['parse', join(root, path), '-o', binary]);
  execFileSync('wasm-tools', ['validate', binary]);
  const module = new WebAssembly.Module(readFileSync(binary));
  assert.deepEqual(WebAssembly.Module.imports(module).filter(i => i.module === 'rocq').map(i => i.name).sort(),
    ['mem_ptr', 'memory', 'out_of_mem', 'result']);
  return new WebAssembly.Instance(module, { rocq: h.rocq, ...imports }).exports;
}

// Canonical list results allocate through the adapter's actual cabi_realloc.
function listResult(h, exports, ret, data, offset = 4) {
  const p = exports.cabi_realloc(0, 0, 1, data.length);
  new Uint8Array(h.rocq.memory.buffer).set(data, p);
  h.put(ret + offset, p);
  h.put(ret + offset + 4, data.length);
}

try {
  {
    const h = heap();
    let outcome = 0;
    let calls = 0;
    const password = [0, 128, 255], salt = [1, 2], expected = [254, 0];
    let enrollPassword = password, enrollError = false, enrollCalls = 0;
    const record = [...Buffer.from(JSON.stringify({
      algorithm: 2, memory_kib: 19456, iterations: 2, parallelism: 1,
      tag_length: 32, salt: 'AAECAwQFBgcICQoLDA0ODw==', tag: 'AP+A',
    }))];
    const costs = [2, 19456, 2, 1, 32];
    const e = instantiate('crypto/argon2/adapter.wat', h, {
      'authentikate:crypto/argon2@0.1.0': {
        'recommended-params': () => assert.fail('verify must use stored parameters'),
        derive: () => assert.fail('verify must not derive a tag'),
        enroll(pp, pl, ret) {
          enrollCalls++;
          assert.deepEqual(h.flat(pp, pl), enrollPassword);
          h.put(ret, Number(enrollError));
          if (!enrollError) listResult(h, e, ret, record);
          else { h.put(ret + 4, 0); h.put(ret + 8, 0); }
        },
        verify(pp, pl, sp, sl, ...args) {
          calls++;
          assert.deepEqual(h.flat(pp, pl), password);
          assert.deepEqual(h.flat(sp, sl), salt);
          assert.deepEqual(args.slice(0, 5), costs);
          const [ep, el, ret] = args.slice(5);
          assert.deepEqual(h.flat(ep, el), expected);
          h.put(ret, outcome === 2 ? 1 : 0);
          h.put(ret + 4, outcome === 1 ? 1 : 0);
        },
      },
    });
    const args = [h.bytes(password), h.bytes(salt), h.block(0, ...costs.map(h.N)), h.bytes(expected)];
    for (outcome of [0, 1, 2]) {
      const result = h.call(e.ffi_argon2_verify, ...args);
      if (outcome === 2) assert.equal(result, 1);
      else assert.equal(h.some(result), outcome === 1 ? 3 : 1);
    }
    assert.equal(calls, 3);
    for (const value of [1, h.bytes(password)]) {
      const before = h.rocq.mem_ptr.value;
      assert.equal(h.call(e.ffi_secret_of_bytes, value), value);
      assert.equal(h.rocq.mem_ptr.value, before, 'identity must not copy secret bytes');
    }
    for (enrollPassword of [password, []]) {
      const secret = h.call(e.ffi_secret_of_bytes, h.bytes(enrollPassword));
      enrollError = false;
      assert.deepEqual(h.unbytes(h.some(h.call(e.ffi_argon2_enroll, secret))), record);
      enrollError = true;
      assert.equal(h.call(e.ffi_argon2_enroll, secret), 1);
    }
    assert.equal(enrollCalls, 4);
    console.log('argon2: void/global ABI, stored parameters, Some false/true vs None, secret identity, enrollment JSON/error');
  }

  {
    const h = heap();
    let outcome = 0, handle = 0, signCalls = 0, publicCalls = 0;
    const message = [0, 255, 128], publicKey = Array.from({ length: 32 }, (_, i) => i);
    const signature = Array.from({ length: 64 }, (_, i) => 255 - i);
    const e = instantiate('crypto/ed25519/adapter.wat', h, {
      'authentikate:crypto/ed25519@0.1.0': {
        sign(key, mp, ml, ret) {
          signCalls++;
          assert.equal(key >>> 0, handle);
          assert.deepEqual(h.flat(mp, ml), message);
          h.put(ret, outcome === 2 ? 1 : 0);
          if (outcome !== 2) listResult(h, e, ret, signature);
        },
        'public-key'(key, ret) {
          publicCalls++;
          assert.equal(key >>> 0, handle);
          h.put(ret, 0);
          listResult(h, e, ret, publicKey);
        },
        verify(kp, kl, mp, ml, sp, sl, ret) {
          assert.deepEqual(h.flat(kp, kl), publicKey);
          assert.deepEqual(h.flat(mp, ml), message);
          assert.deepEqual(h.flat(sp, sl), signature);
          h.put(ret, outcome === 2 ? 1 : 0);
          h.put(ret + 4, outcome === 1 ? 1 : 0);
        },
      },
    });
    const msg = h.bytes(message);
    for (handle of [0, 1, 2, 17, 0x80000000, 0xffffffff]) {
      assert.deepEqual(h.unbytes(h.some(h.call(e.ffi_ed25519_sign, h.N(handle), msg))), signature);
      assert.deepEqual(h.unbytes(h.some(e.ffi_ed25519_public_key(h.N(handle)))), publicKey);
    }
    const beforeSign = signCalls, beforePublic = publicCalls;
    for (const n of [0x100000000n, 0x100000001n, 1n << 80n]) {
      assert.equal(h.call(e.ffi_ed25519_sign, h.N(n), msg), 1);
      assert.equal(e.ffi_ed25519_public_key(h.N(n)), 1);
    }
    assert.equal(signCalls, beforeSign, 'overflow must not reach component');
    assert.equal(publicCalls, beforePublic);
    outcome = 2;
    assert.equal(h.call(e.ffi_ed25519_sign, h.N(handle = 42), msg), 1);
    const args = [h.bytes(publicKey), msg, h.bytes(signature)];
    for (outcome of [0, 1, 2]) {
      const result = h.call(e.ffi_ed25519_verify, ...args);
      if (outcome === 2) assert.equal(result, 1);
      else assert.equal(h.some(result), outcome === 1 ? 3 : 1);
    }
    // The Rocq heap and canonical allocations share memory even across growth.
    outcome = 0;
    h.rocq.mem_ptr.value = 65532;
    assert.deepEqual(h.unbytes(h.some(h.call(e.ffi_ed25519_sign, h.N(handle), msg))), signature);
    assert.ok(h.rocq.memory.buffer.byteLength > 65536);
    console.log('ed25519: checked N handles, signature round trip, refusal, false/true vs None, memory growth');
  }

  for (const openError of [false, true]) {
    const h = heap();
    let mode = 'value', opens = 0, gets = 0, sets = 0, setError = false;
    const key = [...Buffer.from('user@example.test')], value = [0, 255, 128, 65];
    let setValue = [...Buffer.from('{"salt":"AAECAwQFBgcICQoLDA0ODw==","tag":"AP+A"}')];
    const e = instantiate('store/adapter.wat', h, {
      'wasi:keyvalue/store@0.2.0-draft': {
        open(p, n, ret) {
          opens++;
          assert.equal(n, 0);
          assert.equal(p, 0);
          // Full variant error layout: writing all 16 bytes must not overlap
          // the next allocation, even for other(string).
          assert.ok(h.rocq.mem_ptr.value >= ret + 16);
          h.put(ret, Number(openError));
          h.put(ret + 4, openError ? 2 : 7);
          h.put(ret + 8, 0);
          h.put(ret + 12, 0);
        },
        '[method]bucket.get'(bucket, kp, kl, ret) {
          gets++;
          assert.equal(bucket, 7);
          assert.deepEqual(h.flat(kp, kl), key);
          h.put(ret, mode === 'refusal' ? 1 : 0);
          h.put(ret + 4, mode === 'missing' ? 0 : mode === 'refusal' ? 2 : 1);
          if (mode === 'value' || mode === 'empty') listResult(h, e, ret, mode === 'empty' ? [] : value, 8);
          else { h.put(ret + 8, 0); h.put(ret + 12, 0); }
        },
        '[method]bucket.set'(bucket, kp, kl, vp, vl, ret) {
          sets++;
          assert.equal(bucket, 7);
          assert.deepEqual(h.flat(kp, kl), key);
          assert.deepEqual(h.flat(vp, vl), setValue);
          // Fill the entire result<_, error> return area, including the
          // other(string) payload, without overwriting flattened arguments.
          h.put(ret, Number(setError));
          h.put(ret + 4, 2);
          h.put(ret + 8, 0);
          h.put(ret + 12, 0);
          assert.deepEqual(h.flat(kp, kl), key);
          assert.deepEqual(h.flat(vp, vl), setValue);
        },
      },
    });
    const k = h.bytes(key);
    if (openError) {
      assert.equal(h.call(e.ffi_kv_set, k, h.bytes(setValue)), 1);
      assert.equal(h.call(e.ffi_kv_get, k), 1);
      assert.equal(h.call(e.ffi_kv_get, k), 1);
      assert.equal(opens, 3, 'failed open must be retried across set/get');
      assert.equal(gets, 0);
      assert.equal(sets, 0);
    } else {
      // Set opens the bucket; get and subsequent writes reuse the same handle.
      assert.equal(h.some(h.call(e.ffi_kv_set, k, h.bytes(setValue))), 3);
      setError = true;
      assert.equal(h.call(e.ffi_kv_set, k, h.bytes(setValue)), 1);
      setError = false;
      for (setValue of [value, []]) {
        assert.equal(h.some(h.call(e.ffi_kv_set, k, h.bytes(setValue))), 3);
      }
      assert.equal(sets, 4);
      assert.deepEqual(h.unbytes(h.some(h.some(h.call(e.ffi_kv_get, k)))), value);
      mode = 'empty';
      assert.equal(h.some(h.some(h.call(e.ffi_kv_get, k))), 1);
      mode = 'missing';
      assert.equal(h.some(h.call(e.ffi_kv_get, k)), 1);
      mode = 'refusal';
      assert.equal(h.call(e.ffi_kv_get, k), 1);
      assert.equal(opens, 1, 'successful bucket must be cached');
    }
    const before = [opens, gets, sets];
    for (const invalid of [[255], [0xc0, 0xaf], [0xed, 0xa0, 0x80]]) {
      assert.equal(h.some(h.call(e.ffi_kv_get, h.bytes(invalid))), 1);
      assert.equal(h.call(e.ffi_kv_set, h.bytes(invalid), h.bytes(setValue)), 1);
    }
    assert.deepEqual([opens, gets, sets], before, 'invalid UTF-8 must not reach host');
  }
  console.log('store: nested options, exact set JSON/binary/empty bytes, acknowledgment/refusal, shared bucket retry/cache, UTF-8 rejection');
  console.log('All FFI adapter tests passed; all three modules parsed and validated with wasm-tools.');
} finally {
  rmSync(temp, { recursive: true, force: true });
}
