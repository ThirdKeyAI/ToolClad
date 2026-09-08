import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { executeHttp } from '../src/executor.js';

test('asynchronous HTTP execution enforces the same contract boundary', async () => {
  const requests = [];
  const server = createServer((req, res) => {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      requests.push({ path: req.url, body });
      if (req.url === '/redirect') { res.writeHead(302, { Location: '/trap' }); res.end(); }
      else if (req.url === '/large') { res.writeHead(200); res.end('x'.repeat(5 * 1024 * 1024)); }
      else if (req.url === '/slow') { /* The deadline must terminate this open response. */ }
      else { res.writeHead(200); res.end(body); }
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const name = 'TOOLCLAD_SECRET_ASYNC_FIXTURE';
  const previous = process.env[name];
  process.env[name] = 'synthetic "quoted" \\ value';
  const manifest = {
    tool: { name: 'async_fixture', timeout_seconds: 1 },
    args: { value: { type: 'enum', allowed: ['{_secret:async_fixture}'], required: true } },
    http: { url: origin + '/ok', method: 'POST', body_template: '{"value":"{value}","secret":"{_secret:async_fixture}"}' },
  };
  const args = { value: '{_secret:async_fixture}' };
  try {
    const result = await executeHttp(manifest, args);
    assert.equal(result.status, 'success');
    assert.deepEqual(JSON.parse(requests[0].body), { value: args.value, secret: process.env[name] });
    const preview = await executeHttp(manifest, args, { dryRun: true });
    assert.equal(preview.status, 'dry_run');
    assert.equal(JSON.parse(preview.http_body).secret, '[REDACTED]');
    delete process.env[name];
    await executeHttp(manifest, args, { dryRun: true });
    process.env[name] = 'synthetic';
    await assert.rejects(executeHttp({ ...manifest, tool: { ...manifest.tool, human_approval: true } }, args), /embedding runtime/);
    await assert.rejects(executeHttp(manifest, { ...args, unknown: 'no' }), /Unknown argument/);
    assert.equal(requests.length, 1);
    const redirect = await executeHttp({ ...manifest, http: { ...manifest.http, url: origin + '/redirect' } }, args);
    assert.equal(redirect.status, 'error');
    assert.equal(requests.some(r => r.path === '/trap'), false);
    await assert.rejects(executeHttp({ ...manifest, http: { ...manifest.http, url: origin + '/large' } }, args), /exceeds 4 MiB/);
    await assert.rejects(executeHttp({ ...manifest, http: { ...manifest.http, url: origin + '/slow' } }, args), /timed out/);
  } finally {
    if (previous === undefined) delete process.env[name]; else process.env[name] = previous;
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
});
