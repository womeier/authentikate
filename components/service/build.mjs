// Assemble the extracted service without npm dependencies or replacement crypto.
import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync, cpSync, existsSync, rmSync, mkdtempSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../../', import.meta.url));
const out = resolve(process.argv[2] ?? join(root, 'build'));
mkdirSync(out, { recursive: true });
const run = (tool, args) => execFileSync(tool, args, { cwd: root, stdio: 'inherit' });
const text = path => readFileSync(path, 'utf8');
const parse = (name, wat) => {
  writeFileSync(join(out, `${name}.wat`), wat);
  run('wasm-tools', ['parse', join(out, `${name}.wat`), '-o', join(out, `${name}.wasm`)]);
};

// Balanced function extraction ignores strings and both WAT comment forms.
function form(source, start) {
  let depth = 0, comment = 0, quoted = false;
  for (let i = start; i < source.length; i++) {
    const pair = source.slice(i, i + 2), c = source[i];
    if (comment) {
      if (pair === '(;') { comment++; i++; }
      else if (pair === ';)') { comment--; i++; }
    } else if (quoted) {
      if (c === '\\') i++;
      else if (c === '"') quoted = false;
    } else if (pair === ';;') {
      i = source.indexOf('\n', i);
      if (i < 0) break;
    } else if (pair === '(;') { comment++; i++; }
    else if (c === '"') quoted = true;
    else if (c === '(') depth++;
    else if (c === ')' && --depth === 0) return source.slice(start, i + 1);
  }
  throw new Error('Unbalanced WAT form');
}

run('wasm-tools', ['print', join(root, 'build/Authentikate.extraction.authentikate_api.wasm'), '-o', join(out, 'rocq.original.wat')]);
let rocq = text(join(out, 'rocq.original.wat'));
const keep = new Set(['main_function', 'memory', 'result', 'mem_ptr', 'out_of_mem']);
rocq = rocq.replace(/  \(export "([^"]+)"[^\n]+\n/g, (line, name) => keep.has(name) ? line : '');
rocq = rocq.replace(/\n\)\s*$/, '\n  (export "table" (table 0))\n)');
const ffiNames = new Set([
  'ffi_argon2_verify', 'ffi_argon2_enroll', 'ffi_secret_of_bytes',
  'ffi_ed25519_sign', 'ffi_ed25519_verify', 'ffi_kv_get', 'ffi_kv_set',
  'ffi_email_send',
]);
// The service boundary restores heap alignment after the byte-oriented adapters.
rocq = rocq.replace(/\(import "env" "([^"]+)"/g,
  (line, name) => ffiNames.has(name) ? `(import "service" "${name}"` : line);
// CertiRocq populates the table with every import, including unused builtins.
// A closure code pointer is stored literally at field +4. Check both that
// construction pattern and direct/static-indirect calls before dropping slots.
for (const match of rocq.matchAll(/\(import "env" "([^"]+)" \(func \(;(\d+);\)/g)) {
  const [, name, index] = match;
  const direct = new RegExp(`\\b(?:return_)?call ${index}\\b`);
  const indirect = new RegExp(`i32\\.const ${index}\\s+(?:return_)?call_indirect\\b`);
  const closure = new RegExp(`i32\\.const 4\\s+i32\\.add\\s+i32\\.const ${index}\\s+i32\\.store\\b`);
  if (direct.test(rocq) || indirect.test(rocq) || closure.test(rocq)) {
    throw new Error(`Builtin ${name} is referenced; an actual implementation is required`);
  }
  rocq = rocq.replace(new RegExp(`  \\(elem \\(;\\d+;\\) \\(i32\\.const ${index}\\) func ${index}\\)\\n`), '');
}
parse('rocq', rocq);
const argon = text(join(root, 'components/service/adapters/argon2.wat'));
const helpers = ['$alloc', '$list_len', '$read_N', '$lower', '$lift_bytes'].map(name => {
  const start = argon.indexOf(`(func ${name} `);
  if (start < 0) throw new Error(`Missing adapter helper ${name}`);
  return form(argon, start);
}).join('\n');
parse('service', text(join(root, 'components/service/adapters/service.wat')).replace(';; @HEAP_HELPERS@', helpers));
for (const name of ['argon2', 'ed25519', 'store', 'email']) {
  // Only the wrapper allocator and public service functions survive the merge.
  let adapter = text(join(root, 'components/service/adapters', `${name}.wat`));
  if (name === 'email') {
    const store = text(join(root, 'components/service/adapters/store.wat'));
    const emailHelpers = [
      ...['$alloc', '$list_len', '$lower'].map(name => form(argon, argon.indexOf(`(func ${name} `))),
      ...['$some', '$utf8_ok'].map(name => form(store, store.indexOf(`(func ${name} `))),
    ].join('\n');
    adapter = adapter.replace(';; @EMAIL_HELPERS@', emailHelpers);
  }
  adapter = adapter.replace(/\(export "([^"]+)"\)/g, (match, name) => name.startsWith('ffi_') ? match : '');
  parse(name, adapter);
}
run('wasm-merge', ['rocq', 'argon2', 'ed25519', 'store', 'email', 'service'].flatMap(name => [join(out, `${name}.wasm`), name])
  .concat(['--enable-multimemory', '--enable-tail-call', '--rename-export-conflicts', '-o', join(out, 'merged.wasm')]));
run('wasm-tools', ['print', join(out, 'merged.wasm'), '-o', join(out, 'merged.wat')]);
let merged = text(join(out, 'merged.wat'));
// Link-only exports must not keep unused primitives alive.
merged = merged.replace(/  \(export "([^"]+)"[^\n]+\n/g, (line, name) =>
  name === 'memory' || name === 'cabi_realloc' || name.startsWith('authentikate:service/api@') ? line : '');
parse('linked', merged);
run('wasm-opt', [join(out, 'linked.wasm'), '--enable-tail-call', '--remove-unused-module-elements', '--directize',
  '--remove-unused-module-elements', '-o', join(out, 'authentikate.core.wasm')]);
const module = new WebAssembly.Module(readFileSync(join(out, 'authentikate.core.wasm')));
const unexpected = WebAssembly.Module.imports(module).filter(i => ![
  'wasi:keyvalue/store@0.2.0-draft', 'authentikate:crypto/argon2@0.1.0',
  'authentikate:crypto/ed25519@0.1.0',
  'authentikate:email/sender@0.1.0',
  'wasi:clocks/wall-clock@0.2.0',
].includes(i.module));
if (unexpected.length) throw new Error(`Unresolved imports: ${JSON.stringify(unexpected)}`);

// Stage the authoritative dependency sources, not a second manual crypto WIT.
const wit = mkdtempSync(join(out, 'wit-'));
try {
  cpSync(join(root, 'components/service/wit'), wit, { recursive: true });
  cpSync(join(root, 'components/crypto/wit'), join(wit, 'deps/crypto'), { recursive: true });
  cpSync(join(root, 'components/email/wit'), join(wit, 'deps/email'), { recursive: true });
  if (existsSync(join(root, 'components/crypto/wit/deps'))) {
    cpSync(join(root, 'components/crypto/wit/deps'), join(wit, 'deps'), { recursive: true });
  }
  run('wasm-tools', ['component', 'embed', wit, '--world', 'service', join(out, 'authentikate.core.wasm'),
    '-o', join(out, 'authentikate.embedded.wasm')]);
} finally {
  rmSync(wit, { recursive: true, force: true });
}
run('wasm-tools', ['component', 'new', join(out, 'authentikate.embedded.wasm'),
  '-o', join(out, 'authentikate.component.wasm')]);
run('wasm-tools', ['validate', join(out, 'authentikate.component.wasm')]);
console.log(`Built ${join(out, 'authentikate.component.wasm')}`);
