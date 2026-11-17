// Temporary diagnostic consumer: old Actions CLI + fixed public Runtime, never full acceptance.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {appendFileSync, readFileSync, writeFileSync} from 'node:fs';
import {join, resolve} from 'node:path';
import {consumePublishedTarget, downloadPublishedAsset, inspectPublishedRelease, inspectRuntimeProducer} from '../npm/scripts/extract-artifact.mjs';

const root = resolve(process.argv[2]);
try {
  const bytes = readFileSync('scripts/fixtures/arm64-ai-native-20261118.json');
  const manifestHash = createHash('sha256').update(bytes).digest('hex');
  assert.equal(manifestHash, '29dffa8d41d52070df33db4c916512a64429c943910c8b77074832e12653ac26');
  const fixed = JSON.parse(bytes), spec = JSON.parse(readFileSync(join(root, 'consumer-input.json')));
  assert.deepEqual(spec.runtime, fixed.runtime);
  const options = {token: process.env.GH_TOKEN};
  await inspectPublishedRelease(spec.runtime, options);
  const producer = await inspectRuntimeProducer(spec.runtime, fixed.target, options);
  for (const asset of spec.runtime.assets) await downloadPublishedAsset(spec.runtime, asset, join(root, 'assets/runtime'), options);
  // Default consumer reads compatibility and frontend manifests from the original product source.
  const consumed = await consumePublishedTarget(spec, fixed.target, join(root, 'assets'), join(root, 'consumed'), manifestHash, options);
  assert.equal(consumed.identity.cli_binary_sha256, fixed.binary_sha256);
  const provenancePath = join(root, 'provenance.json');
  const provenance = JSON.parse(readFileSync(provenancePath));
  provenance.runtime_producer = producer;
  // Do not copy local paths or process identity fields to the public diagnostic report.
  provenance.products_verified = true;
  writeFileSync(provenancePath, JSON.stringify(provenance, null, 2) + '\n');
  for (const [key, value] of Object.entries(consumed.env)) {
    assert.ok(!/[\r\n]/.test(value));
    appendFileSync(process.env.GITHUB_ENV, `${key}=${value}\n`);
  }
  appendFileSync(process.env.GITHUB_ENV, `CLI_SHA=${fixed.cli.sha}\n`);
  console.log(JSON.stringify({stage: 'strict_single_target_consumption', passed: true, manifest_sha256: manifestHash}));
} catch (error) {
  console.log(JSON.stringify({stage: 'strict_single_target_consumption', passed: false, error_type: error.name}));
  process.exitCode = 1;
}
