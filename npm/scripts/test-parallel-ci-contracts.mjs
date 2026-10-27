import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
const ci=readFileSync(new URL('../../.github/workflows/ci.yml',import.meta.url),'utf8');
const section=name=>ci.split(`\n  ${name}:\n`)[1]?.split(/\n  [a-z][\w-]*:\n/)[0];
test('independent contract checks do not wait for Rust coverage or receive SDK/publish credentials',()=>{
  const contracts=section('contract-checks'),source=section('check');
  assert(contracts && source);assert.doesNotMatch(contracts,/\n    needs:|id-token:|actions: write|secrets\.|fetch-core-sdk|cargo /);
  assert.match(contracts,/persist-credentials: false/);assert.match(contracts,/contents: read/);
  assert.match(source,/cargo test --workspace --exclude respire --locked/);
  assert.match(source,/cargo llvm-cov --locked -p respire --fail-under-lines 90/);
  assert.match(source,/exit "\$result"/);assert.match(source,/RSRS_CORE_TEST_MODE: '1'/);
  for(const script of ['test-publication-acceptance','test-cleanup-release-artifacts','test-registry-publication','test-release-publication','test-dev6-publication-recovery','test-parallel-publication']) {
    assert(contracts.includes(`npm/scripts/${script}.mjs`),script);assert(!source.includes(`npm/scripts/${script}.mjs`),`not serialized: ${script}`);
  }
  for(const script of ['test-private-sdk-download.mjs','test-sdk-ci-cache.mjs','test-stage-core-runtime.mjs','test-dev-smoke-gate.py','test-dev-api-contract.py','test-dev-model-fixture.py','test-dev-fixture-tty.py','test-dev-witness-fixture.py','test-reembed-progress-contract.ps1','test-core-payload-lifetime.py'])assert(contracts.includes(script),script);
});
test('fail-closed aggregate requires both successful lanes, including failure and unexpected skips',()=>{
  const complete=section('check-complete');assert.match(complete,/always\(\)/);assert.match(complete,/needs: \[check, contract-checks\]/);
  assert.match(complete,/test "\$SOURCE_RESULT" = success && test "\$CONTRACT_RESULT" = success/);
  assert.match(complete,/permissions: \{\}/);
  for(const name of ['check','contract-checks'])assert.match(section(name),/!inputs.research_feedback_only && !inputs.native_published_only && !inputs.artifact_run && !inputs.version_upgrade_only/);
});
