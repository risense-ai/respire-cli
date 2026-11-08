import assert from 'node:assert/strict';
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
  return response.json();
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
assert.deepEqual(transport.scope, Object.fromEntries(
  ['account_id', 'instance_id', 'generation'].map(key => [key, before[key]])));
assert.equal(envelope.memory_context?.memory_text_authority, 'untrusted_historical_context');
const after = await health();
for (const key of ['pid', 'instance_id', 'process_start_id', 'image_sha256', 'runtime_version']) {
  assert.equal(after[key], before[key], `Plugin request changed Runtime identity: ${key}`);
}
console.log(JSON.stringify({passed: true, original_rpc: true, scope_bound: true,
  memory_authority_preserved: true, same_runtime: true}));
