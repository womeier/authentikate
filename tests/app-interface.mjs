import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';

const backend = process.argv[2] ?? 'stdout';
assert(['stdout', 'smtp'].includes(backend), 'Expected stdout or smtp backend');
assert(process.argv.length <= 3, 'Usage: node tests/app-interface.mjs [stdout|smtp]');
const artifact = backend === 'smtp' ? 'build/app-live.component.wasm' : 'build/app.component.wasm';
const wit = execFileSync('wasm-tools', ['component', 'wit', artifact], { encoding: 'utf8' });
const interfaces = kind => [...wit.matchAll(new RegExp(`^  ${kind} ([^;]+);$`, 'gm'))]
  .map(match => match[1]).sort();

// Keep capabilities explicit: composing a provider must not silently add egress
// or environment access, or leave application-specific imports for a custom host.
assert.deepEqual(interfaces('import'), [
  ...(backend === 'smtp' ? [
    'wasi:sockets/instance-network@0.2.4',
    'wasi:sockets/network@0.2.4',
    'wasi:sockets/tcp-create-socket@0.2.4',
    'wasi:sockets/tcp@0.2.4',
  ] : ['wasi:cli/stdout@0.2.4']),
  'wasi:clocks/monotonic-clock@0.2.4',
  'wasi:clocks/wall-clock@0.2.0',
  'wasi:filesystem/preopens@0.2.4',
  'wasi:filesystem/types@0.2.4',
  'wasi:http/types@0.2.4',
  'wasi:io/error@0.2.4',
  'wasi:io/poll@0.2.4',
  'wasi:io/streams@0.2.4',
  'wasi:random/random@0.2.4',
].sort());
assert.deepEqual(interfaces('export'), ['wasi:http/incoming-handler@0.2.4']);
console.log(`${artifact} imports and exports match the ${backend} WASI capability allowlist.`);
