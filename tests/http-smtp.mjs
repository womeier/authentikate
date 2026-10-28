// Real HTTP-to-SMTP integration; only the fake loopback server receives mail.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdir, mkdtemp, rm, stat, writeFile } from 'node:fs/promises';
import http from 'node:http';
import net from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const component = join(root, 'build/app-live.component.wasm');
const wasmtime = process.env.WASMTIME ?? 'wasmtime';
const sender = 'Runtime Tests <runtime@example.test>';

test('real HTTP signup delivers SMTP once, and SMTP rejection preserves the account',
  { timeout: 180_000 }, async t => {
    const sockets = new Set();
    const transactions = [];
    const smtpErrors = [];
    let rejectData = false;
    let directory, child, closed, spawnError;
    let stdout = '', stderr = '';
    const smtp = net.createServer(socket => {
      sockets.add(socket);
      const transaction = { commands: [], data: '', rejected: rejectData };
      transactions.push(transaction);
      let pending = '', inData = false, finishedData = false;
      socket.setEncoding('utf8');
      socket.setTimeout(30_000, () => socket.destroy(new Error('Fake SMTP socket timed out')));
      socket.on('close', () => sockets.delete(socket));
      socket.on('error', error => smtpErrors.push(error.message));
      socket.on('data', chunk => {
        pending += chunk;
        let end;
        while ((end = pending.indexOf('\r\n')) !== -1) {
          const line = pending.slice(0, end);
          pending = pending.slice(end + 2);
          if (inData) {
            if (line !== '.') {
              transaction.data += `${line.replace(/^\.\./, '.')}\r\n`;
              continue;
            }
            inData = false;
            finishedData = true;
            socket.write(transaction.rejected ? '550 Message rejected by test\r\n' : '250 Message accepted\r\n');
            continue;
          }
          transaction.commands.push(line);
          const step = transaction.commands.length;
          if (step === 1 && line === 'EHLO authentikate.local') {
            socket.write('250-fake.example.test\r\n250 OK\r\n');
          } else if (step === 2 && line === 'MAIL FROM:<runtime@example.test>') {
            socket.write('250 Sender accepted\r\n');
          } else if (step === 3 && /^RCPT TO:<[^<>]+@example\.test>$/.test(line)) {
            socket.write('250 Recipient accepted\r\n');
          } else if (step === 4 && line === 'DATA') {
            inData = true;
            socket.write('354 End with a dot\r\n');
          } else if (finishedData && line === 'QUIT') {
            socket.end('221 Bye\r\n');
          } else {
            smtpErrors.push(`Unexpected SMTP command at step ${step}: ${line}`);
            socket.end('500 Unexpected command\r\n');
          }
        }
      });
      socket.write('220 fake.example.test SMTP test server\r\n');
    });

    t.after(async () => {
      try {
        if (child && closed) {
          if (child.exitCode === null && child.signalCode === null && !spawnError) child.kill('SIGTERM');
          const timer = setTimeout(() => child.kill('SIGKILL'), 3000);
          try { await closed; } finally { clearTimeout(timer); }
        }
      } finally {
        for (const socket of sockets) socket.destroy();
        try {
          if (smtp.listening) await new Promise((resolve, reject) => smtp.close(error => error ? reject(error) : resolve()));
        } finally {
          if (directory) await rm(directory, { recursive: true, force: true });
        }
      }
    });

    // Never start the component if port 25 belongs to an actual MTA.
    await new Promise((resolve, reject) => {
      smtp.once('error', error => reject(new Error(
        `Cannot bind fake SMTP server to 127.0.0.1:25 (${error.code}): ${error.message}; refusing to run against another MTA`,
        { cause: error })));
      smtp.listen({ host: '127.0.0.1', port: 25, exclusive: true }, resolve);
    });
    smtp.on('error', error => smtpErrors.push(error.message));
    await stat(component); // A missing real build is a failure, not a skip.
    directory = await mkdtemp(join(tmpdir(), 'authentikate-http-smtp-'));
    for (const name of ['accounts', 'config']) await mkdir(join(directory, name), { mode: 0o700 });
    await writeFile(join(directory, 'config/signing.key'), `${randomBytes(32).toString('base64url')}\n`, { mode: 0o600 });

    const reservation = net.createServer();
    await new Promise((resolve, reject) => {
      reservation.once('error', reject);
      reservation.listen(0, '127.0.0.1', resolve);
    });
    const { port } = reservation.address();
    await new Promise((resolve, reject) => reservation.close(error => error ? reject(error) : resolve()));
    const authority = `127.0.0.1:${port}`;
    await writeFile(join(directory, 'config/config.json'), JSON.stringify({
      service: { issuer: 'runtime-smtp-tests', token_ttl_seconds: 137, email_from: sender },
      policy: { approved_origin: null, approved_authorities: [authority] },
    }), { mode: 0o600 });

    const args = ['serve', '--addr', authority,
      '-S', 'cli=y,inherit-network=y,tcp=y,udp=n,allow-ip-name-lookup=n,inherit-env=n',
      '--max-instance-reuse-count', '1', '--max-concurrent-requests', '1',
      '--max-concurrent-connections', '8', '--no-logging-prefix',
      '-W', 'fuel=2000000000,max-memory-size=134217728,max-memories=8,max-instances=32,max-tables=16,max-wasm-stack=8388608,async-stack-size=16777216',
      '-W', 'timeout=90s',
      '--dir', 'accounts::/accounts', '--dir', 'config::/config', component];
    child = spawn(wasmtime, args, { cwd: directory, stdio: ['ignore', 'pipe', 'pipe'] });
    child.stdout.setEncoding('utf8').on('data', data => { stdout += data; });
    child.stderr.setEncoding('utf8').on('data', data => { stderr += data; });
    child.on('error', error => { spawnError = error; });
    closed = new Promise(resolve => child.once('close', resolve));
    const diagnostics = () => `${wasmtime} ${args.join(' ')}\n${stdout}\n${stderr}\n${smtpErrors.join('\n')}`;
    const deadline = Date.now() + 60_000;
    while (true) {
      if (spawnError) throw new Error(`Cannot spawn ${wasmtime}: ${spawnError.message}`);
      if (child.exitCode !== null || child.signalCode !== null) throw new Error(`Wasmtime exited before readiness\n${diagnostics()}`);
      try {
        await new Promise((resolve, reject) => {
          const socket = net.connect({ host: '127.0.0.1', port });
          socket.setTimeout(1000, () => socket.destroy(new Error('Readiness probe timed out')));
          socket.once('error', reject);
          socket.once('connect', () => { socket.destroy(); resolve(); });
        });
        break;
      } catch {
        if (Date.now() >= deadline) throw new Error(`Wasmtime readiness timed out\n${diagnostics()}`);
        await delay(50);
      }
    }

    async function post(path, value, expected) {
      const body = JSON.stringify(value);
      const response = await new Promise((resolve, reject) => {
        const req = http.request({ host: '127.0.0.1', port, path, method: 'POST', agent: false,
          signal: AbortSignal.timeout(40_000), headers: {
            connection: 'close', 'content-type': 'application/json', 'content-length': Buffer.byteLength(body),
          } }, res => {
          const chunks = [];
          res.on('data', chunk => chunks.push(chunk));
          res.on('error', reject);
          res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
        });
        req.on('error', reject);
        req.end(body);
      });
      assert.equal(response.status, expected, `${response.body}\n${diagnostics()}`);
      return JSON.parse(response.body);
    }

    function checkMessage(transaction, credentials, rejected) {
      assert.equal(transaction.rejected, rejected);
      assert.deepEqual(transaction.commands.slice(0, 4), [
        'EHLO authentikate.local', 'MAIL FROM:<runtime@example.test>',
        `RCPT TO:<${credentials.email}>`, 'DATA',
      ]);
      assert.ok(transaction.commands.slice(4).every(command => command === 'QUIT'));
      const separator = transaction.data.indexOf('\r\n\r\n');
      assert.ok(separator > 0, 'SMTP DATA must contain MIME headers and body');
      const headers = transaction.data.slice(0, separator).replace(/\r\n[ \t]+/g, ' ');
      const decodeWords = value => value.replace(/=\?UTF-8\?B\?([^?]+)\?=/gi,
        (_, encoded) => Buffer.from(encoded, 'base64').toString('utf8'));
      assert.match(decodeWords(headers), /^From: Runtime Tests <runtime@example\.test>\r\n/);
      assert.ok(headers.split('\r\n').includes(`To: <${credentials.email}>`));
      assert.match(decodeWords(headers), /\r\nSubject: Welcome to Authentikate\r\n/);
      assert.match(headers, /\r\nMIME-Version: 1\.0\r\n/);
      assert.match(headers, /\r\nContent-Type: text\/plain; charset=UTF-8\r\n/);
      assert.match(headers, /\r\nContent-Transfer-Encoding: base64$/);
      const encoded = transaction.data.slice(separator + 4);
      assert.match(encoded, /^(?:[A-Za-z0-9+/=]{1,76}\r\n)+$/);
      const decoded = Buffer.from(encoded.replace(/\r\n/g, ''), 'base64').toString('utf8');
      assert.equal(decoded, 'Your Authentikate account has been created.');
      assert.ok(!`${transaction.commands.join('\n')}${transaction.data}${decoded}${stdout}${stderr}`.includes(credentials.password),
        'SMTP and process output must not disclose the password');
    }

    const first = { email: 'accepted@example.test', password: 'accepted-secret-password' };
    await post('/api/signup', first, 201);
    assert.equal(transactions.length, 1);
    checkMessage(transactions[0], first, false);
    await post('/api/signup', first, 409);
    assert.equal(transactions.length, 1, 'duplicate signup must not open another SMTP connection');

    rejectData = true;
    const second = { email: 'rejected@example.test', password: 'rejected-secret-password' };
    await post('/api/signup', second, 500);
    assert.equal(transactions.length, 2, 'rejected signup must reach the fake SMTP DATA response');
    checkMessage(transactions[1], second, true);
    const { token } = await post('/api/login', second, 200);
    assert.equal(typeof token, 'string');
    assert.ok(token.length > 0, 'SMTP rejection must leave a usable committed account');
    await post('/api/signup', second, 409);
    assert.equal(transactions.length, 2, 'login and retry must not resend rejected mail');
    assert.deepEqual(smtpErrors, [], diagnostics());
  });
