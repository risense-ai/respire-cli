import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
const ci=readFileSync(new URL('../../.github/workflows/ci.yml',import.meta.url),'utf8');
const section=name=>ci.split(`\n  ${name}:\n`)[1]?.split(/\n  [a-z][\w-]*:\n/)[0];
test('independent contract checks do not wait for Rust coverage or receive SDK/publish credentials',()=>{
  const contracts=section('contract-checks'),source=section('check'),workspace=section('workspace-tests');
  assert(contracts && source);assert.doesNotMatch(contracts,/\n    needs:|id-token:|actions: write|secrets\.|fetch-core-sdk|cargo /);
  assert.match(contracts,/persist-credentials: false/);assert.match(contracts,/contents: read/);
  assert.match(workspace,/cargo test --workspace --exclude respire --locked/);assert.doesNotMatch(source,/cargo test --workspace --exclude respire/);assert.doesNotMatch(workspace,/llvm-cov|needs:/);assert.match(workspace,/Require the exact SDK cache match/);assert.match(workspace,/RSRS_CORE_TEST_MODE: '1'/);
  assert(workspace.indexOf('cargo test --workspace --exclude respire --locked')<workspace.indexOf('python3 scripts/test-core-payload-lifetime.py'));assert(workspace.includes('python3 scripts/test-core-payload-lifetime.py'));assert.doesNotMatch(contracts,/test-core-payload-lifetime.py/);assert(workspace.includes('python3 scripts/test-ci-source-profile.py'));
  assert.match(source,/cargo llvm-cov --locked -p respire --fail-under-lines 90/);
  assert.match(source,/exit "\$result"/);assert.match(source,/RSRS_CORE_TEST_MODE: '1'/);
  for(const script of ['test-publication-fence','test-publication-acceptance','test-cleanup-release-artifacts','test-registry-publication','test-release-publication','test-dev6-publication-recovery','test-parallel-publication']) {
    assert(contracts.includes(`npm/scripts/${script}.mjs`),script);assert(!source.includes(`npm/scripts/${script}.mjs`),`not serialized: ${script}`);
  }
  for(const script of ['test-private-sdk-download.mjs','test-sdk-ci-cache.mjs','test-stage-core-runtime.mjs','test-dev-smoke-gate.py','test-dev-api-contract.py','test-dev-model-fixture.py','test-dev-fixture-tty.py','test-dev-witness-fixture.py','test-reembed-progress-contract.ps1'])assert(contracts.includes(script),script);
});
test('fail-closed aggregate requires both successful lanes, including failure and unexpected skips',()=>{
  const complete=section('check-complete');assert.match(complete,/always\(\)/);assert.match(complete,/needs: \[check, workspace-tests, contract-checks\]/);
  assert.match(complete,/test "\$SOURCE_RESULT" = success && test "\$WORKSPACE_RESULT" = success && test "\$CONTRACT_RESULT" = success/);
  assert.match(complete,/permissions: \{\}/);
  for(const name of ['check','workspace-tests','contract-checks'])assert.match(section(name),/!inputs.research_feedback_only && !inputs.native_published_only && !inputs.artifact_run && !inputs.version_upgrade_only/);
});


test('explicit manual source checks omit only the optional compile matrix and cannot replace Release push-CI proof',()=>{
  assert.match(ci,/source_checks_only:\n        description: Run all source tests, coverage and contracts/);
  assert.match(section('platform-build'),/!inputs.source_checks_only/);
  for(const name of ['workspace-tests','check','contract-checks','check-complete'])assert.doesNotMatch(section(name),/!inputs.source_checks_only/);
  const release=readFileSync(new URL('../../.github/workflows/release.yml',import.meta.url),'utf8');
  assert.match(release,/run.head_sha===sha&&run.event==='push'/);
});


test('source metadata optimization retains unoptimized tests, debug assertions, overflow checks and coverage gate',()=>{
  for(const name of ['workspace-tests','check']){
    const text=section(name);
    for(const profile of ['DEV','TEST']){
      assert(text.includes(`CARGO_PROFILE_${profile}_DEBUG: line-tables-only`));
      assert(text.includes(`CARGO_PROFILE_${profile}_DEBUG_ASSERTIONS: 'true'`));
      assert(text.includes(`CARGO_PROFILE_${profile}_OVERFLOW_CHECKS: 'true'`));
      assert(text.includes(`CARGO_PROFILE_${profile}_OPT_LEVEL: '0'`));
    }
  }
  assert.match(section('check'),/--fail-under-lines 90/);
  assert.doesNotMatch(section('platform-build'),/CARGO_PROFILE_/);
});
