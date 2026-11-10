import assert from 'node:assert/strict';
import {realpathSync} from 'node:fs';
import {resolve} from 'node:path';
import {pathToFileURL} from 'node:url';

assert.equal(process.argv.length, 4);
const [source, endpoint] = process.argv.slice(2);
const url = new URL(endpoint);
assert.equal(url.protocol, 'http:');
assert.equal(url.hostname, '127.0.0.1');
assert.equal(url.pathname, '/');
assert.equal(url.username + url.password + url.search + url.hash, '');

const {options, rpc} = await import(pathToFileURL(resolve(source, 'runtime.mjs')).href);
async function health() {
  const response = await fetch(new URL('api/health', url), {
    redirect: 'error', headers: {'X-Respire-Health': 'runtime-v1'},
    signal: AbortSignal.timeout(5000),
  });
  assert.equal(response.status, 200);
  const value = await response.json();
  assert.equal(value.server, 'respire');
  assert.equal(value.v, 1);
  for (const key of ['pid', 'generation']) {
    assert.ok(Number.isSafeInteger(value[key]) && value[key] > 0, `Invalid Runtime identity: ${key}`);
  }
  for (const key of ['account_id', 'instance_id', 'process_start_id', 'image_sha256',
    'runtime_version', 'installation_root', 'data_dir']) {
    assert.equal(typeof value[key], 'string', `Missing Runtime identity: ${key}`);
    assert.ok(value[key].length > 0, `Empty Runtime identity: ${key}`);
  }
  assert.ok(process.env.RSRS_DATA_DIR, 'Isolated installation root is required');
  assert.equal(realpathSync(value.installation_root), realpathSync(process.env.RSRS_DATA_DIR));
  return value;
}
const before = await health();
// Observe the real transport before the unchanged plugin unwraps result.envelope.
const originalFetch = globalThis.fetch;
let transport;
let requests = 0;
globalThis.fetch = async (input, init) => {
  assert.equal(String(input), new URL('api/rpc', url).href);
  assert.equal(init.method, 'POST');
  const request = JSON.parse(init.body);
  assert.equal(request.v, 1);
  assert.equal(request.method, 'cli.exec');
  assert.deepEqual(request.args, ['--json', 'status']);
  for (const key of ['scope', 'operation_id', 'idempotency_key']) {
    assert.equal(Object.hasOwn(request, key), false);
  }
  requests += 1;
  const response = await originalFetch(input, init);
  assert.equal(response.status, 200);
  transport = await response.clone().json();
  assert.equal(transport.v, 1);
  assert.equal(transport.id, request.id);
  assert.equal(transport.ok, true);
  assert.equal(transport.exit, 0);
  return response;
};
let envelope;
try {
  envelope = await rpc(options({runtimeUrl: endpoint, requestTimeoutMs: 5000}), ['status']);
} finally {
  globalThis.fetch = originalFetch;
}
assert.equal(requests, 1);
assert.deepEqual(envelope, transport.envelope);
assert.equal(envelope.command, 'status');
assert.equal(envelope.status, 'ok');
assert.deepEqual(envelope.errors, []);
// legacy_host::project verifies the captured actor internally, then strips these fields.
for (const key of ['scope', 'operation_id', 'idempotency_key']) {
  assert.equal(Object.hasOwn(transport, key), false);
}
assert.equal(realpathSync(envelope.summary.data_dir), realpathSync(before.data_dir));
const after = await health();
for (const key of ['pid', 'account_id', 'instance_id', 'generation', 'process_start_id',
  'image_sha256', 'runtime_version', 'installation_root', 'data_dir']) {
  assert.equal(after[key], before[key], `Plugin request changed Runtime identity: ${key}`);
}
console.log(JSON.stringify({passed: true, original_rpc: true, legacy_projection_verified: true,
  same_actor_before_after: true, same_runtime: true}));
