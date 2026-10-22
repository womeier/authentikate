// Assemble the extracted service without npm dependencies or replacement crypto.
import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync, cpSync, existsSync, rmSync, mkdtempSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { expandAdapter } from './adapters/expand.mjs';

const root = fileURLToPath(new URL('../../', import.meta.url));
const out = resolve(process.argv[2] ?? join(root, 'build'));
mkdirSync(out, { recursive: true });
const run = (tool, args) => execFileSync(tool, args, { cwd: root, stdio: 'inherit' });
const text = path => readFileSync(path, 'utf8');
const parse = (name, wat) => {
  writeFileSync(join(out, `${name}.wat`), wat);
  run('wasm-tools', ['parse', join(out, `${name}.wat`), '-o', join(out, `${name}.wasm`)]);
};

run('wasm-tools', ['print', join(root, 'build/Authentikate.extraction.authentikate_api.wasm'), '-o', join(out, 'rocq.original.wat')]);
let rocq = text(join(out, 'rocq.original.wat'));
const keep = new Set(['main_function', 'memory', 'result', 'mem_ptr', 'out_of_mem']);
rocq = rocq.replace(/  \(export "([^"]+)"[^\n]+\n/g, (line, name) => keep.has(name) ? line : '');
rocq = rocq.replace(/\n\)\s*$/, '\n  (export "table" (table 0))\n)');
const ffiNames = new Set([
  'ffi_argon2_verify', 'ffi_argon2_hash', 'ffi_secret_of_bytes',
  'ffi_hmac_sign', 'ffi_hmac_verify', 'ffi_kv_get', 'ffi_kv_create',
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
parse('service', expandAdapter(text(join(root, 'components/service/adapters/service.wat'))));
for (const name of ['argon2', 'hmac', 'store', 'email']) {
  // Only the wrapper allocator and public service functions survive the merge.
  let adapter = expandAdapter(text(join(root, 'components/service/adapters', `${name}.wat`)));
  adapter = adapter.replace(/\(export "([^"]+)"\)/g, (match, name) => name.startsWith('ffi_') ? match : '');
  parse(name, adapter);
}
run('wasm-merge', ['rocq', 'argon2', 'hmac', 'store', 'email', 'service'].flatMap(name => [join(out, `${name}.wasm`), name])
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
  'authentikate:storage/accounts@0.1.0',
  'authentikate:crypto/argon2@0.1.0',
  'authentikate:crypto/hmac@0.1.0',
  'authentikate:email/sender@0.1.0',
  'wasi:clocks/wall-clock@0.2.0',
  'authentikate:config/service@0.1.0',
].includes(i.module));
if (unexpected.length) throw new Error(`Unresolved imports: ${JSON.stringify(unexpected)}`);

// Stage the authoritative dependency sources, not a second manual crypto WIT.
const wit = mkdtempSync(join(out, 'wit-'));
try {
  cpSync(join(root, 'components/service/wit'), wit, { recursive: true });
  cpSync(join(root, 'components/crypto/wit'), join(wit, 'deps/crypto'), { recursive: true });
  cpSync(join(root, 'components/email/wit'), join(wit, 'deps/email'), { recursive: true });
  mkdirSync(join(wit, 'deps/config'), { recursive: true });
  cpSync(join(root, 'wit/config.wit'), join(wit, 'deps/config/config.wit'));
  mkdirSync(join(wit, 'deps/storage'), { recursive: true });
  cpSync(join(root, 'wit/accounts.wit'), join(wit, 'deps/storage/accounts.wit'));
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
