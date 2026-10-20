import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createProviders } from './providers.mjs';

const root = new URL('../', import.meta.url);
const output = new URL('build/web-component/', root);
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

export async function createDemoServer() {
  // Compile the real component once; instantiate it afresh to release its bump heap per request.
  execFileSync(process.execPath, [
    fileURLToPath(new URL('node_modules/.bin/jco', root)),
    'transpile', fileURLToPath(new URL('build/authentikate.component.wasm', root)),
    '-o', fileURLToPath(output), '--name', 'service', '--instantiation', 'sync',
    '--no-wasi-shim', '--quiet', '--map',
    'authentikate:crypto/argon2@0.1.0=demo:argon2',
    'authentikate:crypto/ed25519@0.1.0=demo:ed25519',
    'wasi:keyvalue/store@0.2.0-draft=demo:store',
  ], { cwd: fileURLToPath(root), stdio: ['ignore', 'ignore', 'inherit'] });
  const { instantiate } = await import(new URL('service.js', output));
  const modules = new Map();
  const getModule = path => {
    if (!modules.has(path)) modules.set(path, new WebAssembly.Module(readFileSync(new URL(path, output))));
    return modules.get(path);
  };
  const { config, imports } = createProviders();
  // Fail before listening if the component or host bindings cannot be instantiated.
  instantiate(getModule, imports);
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
      const { api } = instantiate(getModule, imports);
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
    console.error('Demo startup failed. Use Node >=24.7, npm install, and build/authentikate.component.wasm.');
    process.exitCode = 1;
  }
}
