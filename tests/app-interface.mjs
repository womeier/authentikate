import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';

const wit = execFileSync('wasm-tools', ['component', 'wit', 'build/app.component.wasm'], { encoding: 'utf8' });
const interfaces = kind => [...wit.matchAll(new RegExp(`^  ${kind} ([^;]+);$`, 'gm'))]
  .map(match => match[1]).sort();

// Keep capabilities explicit: composing a provider must not silently add egress
// or environment access, or leave application-specific imports for a custom host.
assert.deepEqual(interfaces('import'), [
  'wasi:cli/stdout@0.2.4',
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
console.log('Application imports and exports match the WASI capability allowlist.');
