import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
import {runInNewContext} from 'node:vm';
import {cacheKey} from '../../scripts/rust-ci-cache.mjs';
const ci=readFileSync(new URL('../../.github/workflows/ci.yml',import.meta.url),'utf8').replace(/\r\n/g,'\n');
const section=name=>ci.split(`\n  ${name}:\n`)[1]?.split(/\n  [a-z][\w-]*:\n/)[0];
test('independent contract checks do not wait for Rust coverage or receive SDK/publish credentials',()=>{
  const contracts=section('contract-checks'),source=section('coverage-tests'),workspace=section('workspace-tests');
  assert(contracts && source);assert.doesNotMatch(contracts,/\n    needs:|id-token:|actions: write|secrets\.|fetch-core-sdk|cargo /);
  assert.match(contracts,/persist-credentials: false/);assert.match(contracts,/contents: read/);
  assert.match(workspace,/cargo test --workspace --exclude respire --locked/);assert.doesNotMatch(source,/cargo test --workspace --exclude respire/);assert.doesNotMatch(workspace,/llvm-cov|needs:/);assert.match(workspace,/Require the exact SDK cache match/);assert.match(workspace,/RSRS_CORE_TEST_MODE: '1'/);
  assert(workspace.indexOf('cargo test --workspace --exclude respire --locked')<workspace.indexOf('python3 scripts/test-core-payload-lifetime.py'));assert(workspace.includes('python3 scripts/test-core-payload-lifetime.py'));assert.doesNotMatch(contracts,/test-core-payload-lifetime.py/);assert(workspace.includes('python3 scripts/test-ci-source-profile.py'));
  assert.match(source,/group: \[core, runtime_smoke, runtime_autostart\]/);
  assert.match(source,/fail-fast: false/);assert.match(source,/RSRS_CORE_TEST_MODE: '1'/);
  assert.match(source,/targets.filter\(t => t.kind.includes\('test'\)\)/);
  assert.match(source,/tests.filter\(name => !isolated.includes\(name\)\)/);
  assert.match(source,/args.push\('--lib', '--bins', '--examples'\)/);
  assert.match(source,/process.exit\(result.status \?\? 1\)/);
  const program=source.split("node --input-type=module <<'NODE'\n")[1].split('\n          NODE')[0]
    .replace("import {execFileSync, spawnSync} from 'node:child_process';",'');
  const metadata=JSON.parse(execFileSync('cargo',['metadata','--locked','--no-deps','--format-version','1'],{encoding:'utf8'}));
  const targets=metadata.packages.find(p=>p.name==='respire').targets;
  const allTests=targets.filter(t=>t.kind.includes('test')).map(t=>t.name);
  const selected=[];
  for(const group of ['core','runtime_smoke','runtime_autostart']){
    const calls=[],exits=[];
    runInNewContext(program,{
      execFileSync:()=>JSON.stringify(metadata),
      spawnSync:(_command,args)=>{calls.push(args);return {status:0};},
      process:{env:{COVERAGE_GROUP:group},exit:status=>exits.push(status)},
    });
    assert.deepEqual(exits,[0]);assert.equal(calls.length,1);
    for(let i=0;i<calls[0].length;i++)if(calls[0][i]==='--test')selected.push(calls[0][i+1]);
    if(group==='core')for(const flag of ['--lib','--bins','--examples'])assert(calls[0].includes(flag));
  }
  assert.deepEqual(selected.sort(),allTests.sort(),'every integration target must run exactly once');
  const exits=[];
  runInNewContext(program,{
    execFileSync:()=>JSON.stringify(metadata),spawnSync:()=>({status:23}),
    process:{env:{COVERAGE_GROUP:'runtime_smoke'},exit:status=>exits.push(status)},
  });
  assert.deepEqual(exits,[23],'test failures must fail the coverage group');

  const report=section('check');assert.match(report,/needs: coverage-tests/);
  assert.match(report,/for group in core runtime_smoke runtime_autostart/);
  assert.match(report,/cargo llvm-cov report -p respire --fail-under-lines 90/);
  assert.match(report,/exit "\$result"/);
  for(const script of ['test-publication-fence','test-publication-acceptance','test-cleanup-release-artifacts','test-registry-publication','test-release-publication','test-dev6-publication-recovery','test-parallel-publication']) {
    assert(contracts.includes(`npm/scripts/${script}.mjs`),script);assert(!source.includes(`npm/scripts/${script}.mjs`),`not serialized: ${script}`);
  }
  for(const script of ['test-private-sdk-download.mjs','test-sdk-ci-cache.mjs','test-stage-core-runtime.mjs','test-dev-smoke-gate.py','test-dev-api-contract.py','test-dev-model-fixture.py','test-dev-fixture-tty.py','test-dev-witness-fixture.py','test-reembed-progress-contract.ps1'])assert(contracts.includes(script),script);
});
test('fail-closed aggregate requires both successful lanes, including failure and unexpected skips',()=>{
  const complete=section('check-complete');assert.match(complete,/always\(\)/);assert.match(complete,/needs: \[check, workspace-tests, contract-checks\]/);
  assert.match(complete,/test "\$SOURCE_RESULT" = success && test "\$WORKSPACE_RESULT" = success && test "\$CONTRACT_RESULT" = success/);
  assert.match(complete,/permissions: \{\}/);
  for(const name of ['coverage-tests','check','workspace-tests','contract-checks'])assert.match(section(name),/!inputs.research_feedback_only && !inputs.native_published_only && !inputs.artifact_run && !inputs.version_upgrade_only/);
});


test('explicit manual source checks omit only the optional compile matrix and cannot replace Release push-CI proof',()=>{
  assert.match(ci,/source_checks_only:\n        description: Run all source tests, coverage and contracts/);
  assert.match(section('platform-build'),/!inputs.source_checks_only/);
  for(const name of ['workspace-tests','coverage-tests','check','contract-checks','check-complete'])assert.doesNotMatch(section(name),/!inputs.source_checks_only/);
  const release=readFileSync(new URL('../../.github/workflows/release.yml',import.meta.url),'utf8');
  assert.match(release,/run.head_sha===sha&&run.event==='push'/);
});


test('source metadata optimization retains unoptimized tests, debug assertions, overflow checks and coverage gate',()=>{
  for(const name of ['workspace-tests','coverage-tests']){
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
  const manifest=readFileSync(new URL('../../Cargo.toml',import.meta.url),'utf8').replace(/\r\n/g,'\n');
  assert.match(manifest,/\[profile.dev.package.sha2\]\nopt-level = 3/);
  assert.doesNotMatch(manifest,/\[profile\.(?:dev|test)\]\n[^[]*opt-level\s*=\s*[1-3]/);
  assert.doesNotMatch(manifest,/\[profile\.(?:dev|test)\.package\.(?:"\*"|respire[\w-]*)\]/);
  const archive=section('coverage-tests');
  assert.match(archive,/set -euo pipefail/);
  assert.match(archive,/tar -cf -[^\n]+\| gzip -1/);
  assert.match(archive,/compression-level: 0/);
  assert.match(archive,/cargo llvm-cov clean --profraw-only/);
  const identity={rust:'pinned compiler',locks:['dependencies','sdk'],flags:['coverage']};
  const key=cacheKey('coverage',identity);assert.match(key,/^rust-ci-v1-coverage-[a-f0-9]{64}$/);
  assert.equal(key,cacheKey('coverage',structuredClone(identity)));
  assert.notEqual(key,cacheKey('workspace',identity));
  for(const field of Object.keys(identity))assert.notEqual(key,cacheKey('coverage',{...identity,[field]:'changed'}));
  assert.throws(()=>cacheKey('sdk',identity));
  const cacheScript=readFileSync(new URL('../../scripts/rust-ci-cache.mjs',import.meta.url),'utf8');
  assert.match(cacheScript,/preserveTimestamps: true/);
  const writer=section('rust-build-save');
  assert.match(writer,/cache-mode: write-only/);assert.match(writer,/filter='data'/);
  assert.match(writer,/\^rust-ci-v1-/);
  assert.doesNotMatch(writer,/actions\/checkout|secrets\.|cache\/restore|cargo |run: node/);
  for(const name of ['workspace-tests','coverage-tests']){
    const lane=section(name);assert.match(lane,/actions\/cache\/restore/);assert.doesNotMatch(lane,/cache-mode: write|cache\/save/);
    assert.match(lane,/steps.rust-build.outputs.cache-hit != 'true'/);
  }
});
