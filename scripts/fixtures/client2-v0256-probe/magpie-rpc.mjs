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
// Call the unchanged released plugin. Do not synthesize its legacy request.
const envelope = await rpc(options({runtimeUrl: endpoint, requestTimeoutMs: 5000}), ['status']);
assert.equal(envelope.command, 'status');
assert.equal(envelope.status, 'ok');
assert.deepEqual(envelope.errors, []);
assert.deepEqual(envelope.scope, Object.fromEntries(
  ['account_id', 'instance_id', 'generation'].map(key => [key, before[key]])));
assert.equal(envelope.memory_context?.memory_text_authority, 'untrusted_historical_context');
const after = await health();
for (const key of ['pid', 'instance_id', 'process_start_id', 'image_sha256', 'runtime_version']) {
  assert.equal(after[key], before[key], `Plugin request changed Runtime identity: ${key}`);
}
console.log(JSON.stringify({passed: true, original_rpc: true, scope_bound: true,
  memory_authority_preserved: true, same_runtime: true}));
