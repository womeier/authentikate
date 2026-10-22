// nix develop --command node tests/ffi-adapters.mjs
// Exercise actual adapter templates using the production build's expansion.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { expandAdapter } from '../components/service/adapters/expand.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const temp = mkdtempSync(join(tmpdir(), 'ffi-adapters-'));

function heap(maximum = 65536) {
  const memory = new WebAssembly.Memory({ initial: 1, maximum });
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
  const wat = join(temp, path.replaceAll('/', '-'));
  const binary = wat + '.wasm';
  writeFileSync(wat, expandAdapter(readFileSync(join(root, path), 'utf8')));
  execFileSync('wasm-tools', ['parse', wat, '-o', binary]);
  execFileSync('wasm-tools', ['validate', binary]);
  const module = new WebAssembly.Module(readFileSync(binary));
  assert.deepEqual(WebAssembly.Module.imports(module).map(i => `${i.module}#${i.name}:${i.kind}`).sort(), [
    'rocq#memory:memory', 'rocq#mem_ptr:global', 'rocq#out_of_mem:global', 'rocq#result:global',
    ...Object.entries(imports).flatMap(([provider, functions]) =>
      Object.keys(functions).map(name => `${provider}#${name}:function`)),
  ].sort());
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
  assert.throws(() => expandAdapter(';; @COMMON missing@'), /Missing common WAT helper missing/);
  for (const [name, provider, functions] of [
    ['argon2', 'authentikate:crypto/argon2@0.1.0', ['hash', 'verify']],
    ['hmac', 'authentikate:crypto/hmac@0.1.0', ['sign', 'verify']],
    ['store', 'authentikate:storage/accounts@0.1.0', ['get', 'create']],
  ]) {
    const h = heap(1);
    const e = instantiate(`components/service/adapters/${name}.wat`, h, {
      [provider]: Object.fromEntries(functions.map(name => [name, () => assert.fail('unexpected provider call')])),
    });
    h.rocq.mem_ptr.value = 1025;
    const p = e.cabi_realloc(0, 0, 8, 4);
    assert.equal(p, 1032, 'canonical allocation must honor alignment');
    new Uint8Array(h.rocq.memory.buffer).set([1, 128, 255, 4], p);
    const grown = e.cabi_realloc(p, 4, 4, 7);
    assert.deepEqual(h.flat(grown, 4), [1, 128, 255, 4]);
    const shrunk = e.cabi_realloc(grown, 7, 1, 2);
    assert.deepEqual(h.flat(shrunk, 2), [1, 128]);
    assert.equal(e.cabi_realloc(shrunk, 2, 8, 0), 1048);
    assert.equal(h.rocq.mem_ptr.value, 1048, 'zero size still aligns the bump pointer');
    h.rocq.mem_ptr.value = 65532;
    assert.equal(e.cabi_realloc(0, 0, 4, 8), 0, 'failed memory growth returns zero');
    assert.equal(h.rocq.out_of_mem.value, 1);
    assert.equal(h.rocq.mem_ptr.value, 65532, 'failed allocation must not advance the heap');
  }
  console.log('shared allocators: alignment, grow/shrink copying, zero size, OOM flag and unchanged heap');

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
    const e = instantiate('components/service/adapters/argon2.wat', h, {
      'authentikate:crypto/argon2@0.1.0': {
        hash(pp, pl, ret) {
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
      assert.deepEqual(h.unbytes(h.some(h.call(e.ffi_argon2_hash, secret))), record);
      enrollError = true;
      assert.equal(h.call(e.ffi_argon2_hash, secret), 1);
    }
    assert.equal(enrollCalls, 4);
    console.log('argon2: void/global ABI, stored parameters, Some false/true vs None, secret identity, enrollment JSON/error');
  }

  {
    const h = heap();
    let outcome = 0, handle = 0, signCalls = 0, verifyCalls = 0;
    const message = [0, 255, 128];
    const signature = Array.from({ length: 32 }, (_, i) => 255 - i);
    const e = instantiate('components/service/adapters/hmac.wat', h, {
      'authentikate:crypto/hmac@0.1.0': {
        sign(key, mp, ml, ret) {
          signCalls++;
          assert.equal(key >>> 0, handle);
          assert.deepEqual(h.flat(mp, ml), message);
          h.put(ret, outcome === 2 ? 1 : 0);
          if (outcome !== 2) listResult(h, e, ret, signature);
        },
        verify(key, mp, ml, sp, sl, ret) {
          verifyCalls++;
          assert.equal(key >>> 0, handle);
          assert.deepEqual(h.flat(mp, ml), message);
          assert.deepEqual(h.flat(sp, sl), signature);
          h.put(ret, outcome === 2 ? 1 : 0);
          h.put(ret + 4, outcome === 1 ? 1 : 0);
        },
      },
    });
    const msg = h.bytes(message);
    for (handle of [0, 1, 2, 17, 0x80000000, 0xffffffff]) {
      assert.deepEqual(h.unbytes(h.some(h.call(e.ffi_hmac_sign, h.N(handle), msg))), signature);
      assert.equal(h.some(h.call(e.ffi_hmac_verify, h.N(handle), msg, h.bytes(signature))), 1);
    }
    const beforeSign = signCalls, beforeVerify = verifyCalls;
    for (const n of [0x100000000n, 0x100000001n, 1n << 80n]) {
      assert.equal(h.call(e.ffi_hmac_sign, h.N(n), msg), 1);
      assert.equal(h.call(e.ffi_hmac_verify, h.N(n), msg, h.bytes(signature)), 1);
    }
    assert.equal(signCalls, beforeSign, 'overflow must not reach component');
    assert.equal(verifyCalls, beforeVerify, 'overflow must not reach verification either');
    outcome = 2;
    assert.equal(h.call(e.ffi_hmac_sign, h.N(handle = 42), msg), 1);
    const args = [h.N(handle), msg, h.bytes(signature)];
    for (outcome of [0, 1, 2]) {
      const result = h.call(e.ffi_hmac_verify, ...args);
      if (outcome === 2) assert.equal(result, 1);
      else assert.equal(h.some(result), outcome === 1 ? 3 : 1);
    }
    // The Rocq heap and canonical allocations share memory even across growth.
    outcome = 0;
    h.rocq.mem_ptr.value = 65532;
    assert.deepEqual(h.unbytes(h.some(h.call(e.ffi_hmac_sign, h.N(handle), msg))), signature);
    assert.ok(h.rocq.memory.buffer.byteLength > 65536);
    console.log('hmac: checked N handles, signature round trip, refusal, false/true vs None, memory growth');
  }

  {
    const h = heap();
    let mode = 'value', outcome = 'created';
    let gets = 0, creates = 0;
    const key = [...Buffer.from('user@example.test')], value = [0, 255, 128, 65];
    let setValue = [...Buffer.from('{"salt":"AAECAwQFBgcICQoLDA0ODw==","tag":"AP+A"}')];
    const create = (k, v) => h.call(e.ffi_kv_create, k, h.bytes(v));
    const e = instantiate('components/service/adapters/store.wat', h, {
      'authentikate:storage/accounts@0.1.0': {
        get(kp, kl, ret) {
          gets++;
          assert.ok(h.rocq.mem_ptr.value >= ret + 16);
          assert.deepEqual(h.flat(kp, kl), key);
          h.put(ret, mode === 'refusal' ? 1 : 0);
          h.put(ret + 4, mode === 'missing' || mode === 'refusal' ? 0 : 1);
          if (mode === 'value' || mode === 'empty') listResult(h, e, ret, mode === 'empty' ? [] : value, 8);
          else { h.put(ret + 8, 0); h.put(ret + 12, 0); }
        },
        create(kp, kl, vp, vl, ret) {
          creates++;
          assert.deepEqual(h.flat(kp, kl), key);
          assert.deepEqual(h.flat(vp, vl), setValue);
          assert.ok(h.rocq.mem_ptr.value >= ret + 2);
          // result<bool, error> has byte-sized discriminant and payload.
          const memory = new Uint8Array(h.rocq.memory.buffer);
          memory[ret] = Number(outcome === 'refusal');
          memory[ret + 1] = Number(outcome === 'created');
        },
      },
    });
    const k = h.bytes(key);
    assert.equal(h.some(create(k, setValue)), 3);
    outcome = 'taken';
    assert.equal(h.some(create(k, setValue)), 1);
    outcome = 'refusal';
    assert.equal(create(k, setValue), 1);
    outcome = 'created';
    for (setValue of [value, []]) {
      assert.equal(h.some(create(k, setValue)), 3);
    }
    assert.deepEqual(h.unbytes(h.some(h.some(h.call(e.ffi_kv_get, k)))), value);
    mode = 'empty';
    assert.equal(h.some(h.some(h.call(e.ffi_kv_get, k))), 1);
    mode = 'missing';
    assert.equal(h.some(h.call(e.ffi_kv_get, k)), 1);
    mode = 'refusal';
    assert.equal(h.call(e.ffi_kv_get, k), 1);
    assert.deepEqual([gets, creates], [4, 5]);
    const before = [gets, creates];
    for (const invalid of [[255], [0xc0, 0xaf], [0xed, 0xa0, 0x80]]) {
      assert.equal(h.some(h.call(e.ffi_kv_get, h.bytes(invalid))), 1);
      assert.equal(create(h.bytes(invalid), setValue), 1);
    }
    assert.deepEqual([gets, creates], before, 'invalid UTF-8 must not reach provider');
  }
  console.log('accounts: nested options, byte-sized create results (created/taken/refused), binary/empty values, UTF-8 rejection');

  {
    const h = heap();
    let calls = 0, error = -1;
    let fields = ['Authentikate <hello@example.test>', 'user@example.test',
      'Welcome to Authentikate', 'Your Authentikate account has been created.'].map(s => [...Buffer.from(s)]);
    const e = instantiate('components/service/adapters/email.wat', h, {
      'authentikate:email/sender@0.1.0': {
        send(...args) {
          calls++;
          assert.equal(args.length, 12, 'canonical send has 12 i32 parameters');
          const [fp, fn, tp, tn, sp, sn, bp, bn, idem, ip, il, ret] = args;
          assert.equal(tn, 1, 'one recipient, represented as list<string>');
          assert.equal(tp % 4, 0);
          assert.deepEqual([idem, ip, il], [0, 0, 0]);
          const check = () => assert.deepEqual([
            h.flat(fp, fn), h.flat(h.get(tp), h.get(tp + 4)), h.flat(sp, sn), h.flat(bp, bn),
          ], fields);
          check();
          assert.equal(ret % 4, 0);
          assert.ok(h.rocq.mem_ptr.value >= ret + 16, 'result<_, error> must reserve all 16 bytes before host call');
          // String error variants occupy 12 bytes nested inside the result.
          h.put(ret, Number(error >= 0));
          h.put(ret + 4, error < 0 ? 0 : error);
          h.put(ret + 8, error === 3 ? 503 : 0);
          h.put(ret + 12, 0);
          if (error >= 0 && error < 3) {
            const reason = Buffer.from('provider refused');
            const p = h.alloc(reason.length);
            new Uint8Array(h.rocq.memory.buffer).set(reason, p);
            h.put(ret + 8, p); h.put(ret + 12, reason.length);
          }
          check(); // Full result writes must not overlap flattened arguments.
        },
      },
    });
    let args = fields.map(h.bytes);
    assert.equal(h.call(e.ffi_email_send, ...args), 3, 'acceptance returns immediate true');
    for (error of [0, 1, 2, 3]) {
      assert.equal(h.call(e.ffi_email_send, ...args), 1, 'every host error returns immediate false');
    }
    assert.equal(calls, 5);
    const before = calls;
    for (const invalid of [[255], [0xc0, 0xaf], [0xed, 0xa0, 0x80], [0xf4, 0x90, 0x80, 0x80], [0xe2, 0x82], [0x80]]) {
      for (let field = 0; field < 4; field++) {
        const bad = [...args];
        bad[field] = h.bytes(invalid);
        assert.equal(h.call(e.ffi_email_send, ...bad), 1, `invalid UTF-8 in field ${field} returns false`);
        assert.equal(calls, before, 'invalid UTF-8 in any field must not reach the host');
      }
    }
    error = -1;
    fields = ['Fr\u00e9d <hello@example.test>', 'us\u00e9r@example.test', 'Welcome \ud83d\udc4b', 'A\u0000\u20ac\ud83d\ude80'].map(s => [...Buffer.from(s)]);
    args = fields.map(h.bytes);
    h.rocq.mem_ptr.value = h.rocq.memory.buffer.byteLength - 4;
    const beforeGrowth = h.rocq.memory.buffer.byteLength;
    assert.equal(h.call(e.ffi_email_send, ...args), 3);
    assert.ok(h.rocq.memory.buffer.byteLength > beforeGrowth, 'lowering must grow shared memory safely');
    fields = [[], [], [], []];
    assert.equal(h.call(e.ffi_email_send, ...fields.map(h.bytes)), 3, 'empty UTF-8 fields are left to host validation');
    assert.equal(calls, before + 2);
    console.log('email: void/global ABI, exact flat message, immediate true/false, full 16-byte error area, UTF-8 rejection in every field, Unicode/empty bytes, memory growth');
  }
  console.log('All FFI adapter tests passed; all four modules validated with wasm-tools.');
} finally {
  rmSync(temp, { recursive: true, force: true });
}
