// Checks the two hand-written numeric functions in the Wasm adapters: $read_N
// (an N down to an i32) and $utf8_ok (RFC 3629 well-formedness).  Everything
// else in the adapters is translation that only means anything against a real
// component; these two are self-contained arithmetic, so they can be tested,
// and they are the ones where a quiet off-by-one would matter -- $read_N wrong
// means hashing under the wrong cost, $utf8_ok wrong means a trap on
// attacker-controlled input.
//
// Run: test/run.sh
import fs from 'fs';
const m = new WebAssembly.Module(fs.readFileSync(process.argv[2]));
const i = new WebAssembly.Instance(m, {});
const mem = new DataView(i.exports.mem.buffer);
let bump = 1024;
const alloc = n => { const p = bump; bump += n; return p; };
// N / positive encoders, mirroring the representation the adapter documents.
function pos(n) {           // n >= 1
  if (n === 1) return 1;                                   // xH
  const p = alloc(8);
  mem.setInt32(p, n % 2 === 1 ? 0 : 1, true);              // xI tag 0 / xO tag 1
  mem.setInt32(p + 4, pos(Math.floor(n / 2)), true);
  return p;
}
function N(n) {
  if (n === 0) return 1;                                   // N0
  const p = alloc(8);
  mem.setInt32(p, 0, true);
  mem.setInt32(p + 4, pos(n), true);
  return p;
}
let bad = 0;
const cases = [0,1,2,3,4,5,6,7,8,15,16,19456,65535,65536,4294967295,2,1000003];
for (const n of cases) {
  const got = i.exports.read_N(N(n)) >>> 0;
  if (got !== n) { console.log(`read_N FAIL ${n} -> ${got}`); bad++; }
}
console.log(`read_N: ${cases.length - bad}/${cases.length} ok`);

// utf8_ok against node's own decoder as the oracle, which is the reason this
// test is in JavaScript at all: a second implementation of UTF-8 written by
// the same hand would agree with the first one's mistakes.
const dec = new TextDecoder('utf-8', { fatal: true });
const bytes = new Uint8Array(i.exports.mem.buffer);
function check(arr) {
  bytes.set(arr, 512);
  const got = i.exports.utf8_ok(512, arr.length) === 1;
  let want;
  try { dec.decode(new Uint8Array(arr)); want = true; } catch { want = false; }
  return [got, want];
}
const named = {
  'empty': [], 'ascii': [...Buffer.from('a@b.example')],
  'e-acute': [0xC3,0xA9], 'euro': [0xE2,0x82,0xAC], 'emoji': [0xF0,0x9F,0x92,0xA9],
  'lone cont': [0xFF], 'bare 0x80': [0x80], 'overlong /': [0xC0,0xAF],
  'overlong C1': [0xC1,0xBF], 'overlong 3': [0xE0,0x80,0xAF],
  'surrogate D800': [0xED,0xA0,0x80], 'max U+10FFFF': [0xF4,0x8F,0xBF,0xBF],
  'past max': [0xF4,0x90,0x80,0x80], 'F5': [0xF5,0x80,0x80,0x80],
  'truncated 3': [0xE2,0x82], 'truncated 2': [0xC3],
  'ascii then bad': [0x61,0xC3,0x28], 'U+0800': [0xE0,0xA0,0x80],
  'U+FFFD': [0xEF,0xBF,0xBD], 'U+10000': [0xF0,0x90,0x80,0x80],
};
let ubad = 0, utot = 0;
for (const [k,v] of Object.entries(named)) {
  const [got,want] = check(v); utot++;
  if (got !== want) { console.log(`utf8_ok FAIL ${k}: got ${got} want ${want}`); ubad++; }
}
// and a fuzz sweep, including every 1- and 2-byte string
for (let a = 0; a < 256; a++) {
  for (const tail of [[],[0x80],[0xBF],[0x41],[0x80,0x80],[0x80,0x80,0x80],[0xA0,0x80]]) {
    const [got,want] = check([a,...tail]); utot++;
    if (got !== want) { if (ubad < 10) console.log(`utf8_ok FAIL [${[a,...tail]}]: got ${got} want ${want}`); ubad++; }
  }
}
for (let n = 0; n < 20000; n++) {
  const len = 1 + (n % 6);
  const arr = Array.from({length: len}, () => Math.random() < 0.5 ? (Math.random()*256|0) : (0x80 + (Math.random()*128|0)));
  const [got,want] = check(arr); utot++;
  if (got !== want) { if (ubad < 10) console.log(`utf8_ok FAIL [${arr}]: got ${got} want ${want}`); ubad++; }
}
console.log(`utf8_ok: ${utot - ubad}/${utot} ok`);
process.exit(bad + ubad ? 1 : 0);
