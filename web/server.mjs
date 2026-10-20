import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createProviders } from './providers.mjs';

const root = new URL('../', import.meta.url);
const limit = 16 * 1024;

function readBody(request) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    request.on('data', chunk => {
      size += chunk.length;
      if (size > limit) {
        chunks.length = 0;
        reject({ status: 413, message: 'Request body exceeds 16 KiB' });
      } else chunks.push(chunk);
    });
    request.on('end', () => resolve(Buffer.concat(chunks)));
    request.on('error', () => reject({ status: 400, message: 'Request interrupted' }));
    request.on('aborted', () => reject({ status: 400, message: 'Request interrupted' }));
  });
}

async function loadComponent(artifact, name, mappings = []) {
  const output = new URL(`build/web-component/${name}/`, root);
  execFileSync(process.execPath, [
    fileURLToPath(new URL('node_modules/.bin/jco', root)),
    'transpile', fileURLToPath(new URL(`build/${artifact}.component.wasm`, root)),
    '-o', fileURLToPath(output), '--name', name, '--instantiation', 'sync',
    '--no-wasi-shim', '--quiet', ...mappings.flatMap(mapping => ['--map', mapping]),
  ], { cwd: fileURLToPath(root), stdio: ['ignore', 'ignore', 'inherit'] });
  const { instantiate } = await import(new URL(`${name}.js`, output));
  const modules = new Map();
  const getModule = path => {
    if (!modules.has(path)) modules.set(path, new WebAssembly.Module(readFileSync(new URL(path, output))));
    return modules.get(path);
  };
  return imports => instantiate(getModule, imports);
}

export async function createDemoServer({ writeEmail = bytes => process.stdout.write(bytes) } = {}) {
  // Compile once; fresh instances release both components' heaps after each request.
  const service = await loadComponent('authentikate', 'service', [
    'authentikate:crypto/argon2@0.1.0=demo:argon2',
    'authentikate:crypto/ed25519@0.1.0=demo:ed25519',
    'wasi:keyvalue/store@0.2.0-draft=demo:store',
    'authentikate:email/sender@0.1.0=demo:email',
  ]);
  const email = await loadComponent('email-stdout', 'email');
  class OutputStream {
    blockingWriteAndFlush(bytes) {
      // Copy lifted bytes before the component can reuse its memory.
      try { writeEmail(Buffer.from(bytes)); }
      catch { throw { tag: 'closed' }; }
    }
  }
  const emailImports = {
    'wasi:io/error': { Error: class {} },
    'wasi:io/streams': { OutputStream },
    'wasi:cli/stdout': { getStdout: () => new OutputStream() },
  };
  const requestImports = () => ({
    ...imports, 'demo:email': email(emailImports)['authentikate:email/sender@0.1.0'],
  });
  const { config, imports } = createProviders();
  // Fail before listening if the component or host bindings cannot be instantiated.
  service(requestImports());
  const assets = new Map([
    ['/', ['index.html', 'text/html; charset=utf-8']],
    ['/style.css', ['style.css', 'text/css; charset=utf-8']],
    ['/app.js', ['app.js', 'text/javascript; charset=utf-8']],
  ].map(([path, [file, type]]) => [path, { type, body: readFileSync(new URL(file, import.meta.url)) }]));
  const endpoints = new Map(['/api/signup', '/api/login', '/api/validate'].map(path => [path, path.slice(5)]));

  const server = createServer(async (request, response) => {
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('X-Content-Type-Options', 'nosniff');
    response.setHeader('Referrer-Policy', 'no-referrer');
    response.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
    const json = (status, body) => {
      response.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
      response.end(JSON.stringify(body));
    };
    try {
      // Origin alone is insufficient: a rebinding domain can supply a matching Host.
      const host = request.headers.host?.toLowerCase();
      const port = request.socket.localPort;
      const allowedHosts = ['127.0.0.1', 'localhost', '[::1]'].map(name => port === 80 ? name : `${name}:${port}`);
      if (!allowedHosts.includes(host)) {
        json(403, { error: 'Use a loopback host at the listening port' });
        return;
      }
      if (!request.url.startsWith('/') || request.url.startsWith('//')) {
        json(400, { error: 'Use a relative request target' });
        return;
      }
      const path = new URL(request.url, 'http://localhost').pathname;
      const endpoint = endpoints.get(path);
      if (!endpoint) {
        const asset = assets.get(path);
        if (asset && (request.method === 'GET' || request.method === 'HEAD')) {
          response.writeHead(200, { 'Content-Type': asset.type });
          response.end(request.method === 'HEAD' ? undefined : asset.body);
        } else json(404, { error: 'Not found' });
        return;
      }
      if (request.method !== 'POST') {
        response.setHeader('Allow', 'POST');
        json(405, { error: 'Use POST' });
        return;
      }
      if (request.headers.origin && request.headers.origin !== `http://${host}`) {
        json(403, { error: 'Cross-origin requests are not allowed' });
        return;
      }
      if (request.headers['content-type']?.split(';')[0].trim().toLowerCase() !== 'application/json') {
        json(415, { error: 'Use application/json' });
        return;
      }
      if (Number(request.headers['content-length']) > limit) {
        request.resume();
        json(413, { error: 'Request body exceeds 16 KiB' });
        return;
      }
      const body = await readBody(request);
      const { api } = service(requestImports());
      const result = api[endpoint](config, BigInt(Math.floor(Date.now() / 1000)), body);
      response.writeHead(result.status, { 'Content-Type': 'application/json; charset=utf-8' });
      response.end(Buffer.from(result.body));
    } catch (error) {
      // Never log request bodies, component exceptions, tokens, or key material.
      json(error.status === 413 ? 413 : error.status === 400 ? 400 : 500, {
        error: error.status === 413 ? 'Request body exceeds 16 KiB'
          : error.status === 400 ? 'Request interrupted' : 'Component request failed',
      });
    }
  });
  server.requestTimeout = 15000;
  server.headersTimeout = 10000;
  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const server = await createDemoServer();
    const port = Number(process.env.PORT ?? 3000);
    const host = process.env.HOST ?? '127.0.0.1';
    server.on('error', () => { console.error('Demo server could not listen. Check HOST and PORT.'); process.exitCode = 1; });
    server.listen(port, host, () => {
      console.log(`Authentikate demo: http://${host}:${server.address().port}`);
      console.log('Ephemeral demo only. Accounts and signing key are cleared on restart.');
    });
  } catch {
    console.error('Demo startup failed. Use Node >=24.7, npm install, and build/{authentikate,email-stdout}.component.wasm.');
    process.exitCode = 1;
  }
}
