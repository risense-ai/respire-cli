import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {regressionContract,validateRegressionContract,regressionStatus,regressionCompletedAt} from './release-regression-contract.mjs';
import {requireRegressions} from './cleanup-release-artifacts.mjs';
const manifest=JSON.parse(readFileSync(new URL('../artifact-manifest.json',import.meta.url)));
const contract=regressionContract(manifest),copy=structuredClone;
const job=name=>({name,status:'completed',conclusion:'success'});
const inventory=()=>[...contract.native.map(t=>job(`native-regression / Native (${t})`)),...contract.cloud.map(t=>job(`cloud-sweep (runner, ${t})`)),...contract.migration.map(t=>job(`Native migration (${t})`)),...contract.migration_gate.map(t=>job(`Migration gate (${t})`)),job('api-smoke'),job('publish')];
test('new full gate requires every native, cloud, migration fixture, join and API success',()=>{
  validateRegressionContract(contract,manifest);assert.equal(contract.native.length,4);assert.equal(contract.cloud.length,3);assert.equal(contract.migration.length,2);assert.equal(contract.migration_gate.length,2);
  assert.equal(regressionStatus(inventory(),contract),'success');requireRegressions(inventory(),contract.native,contract);
  for(let index=0;index<inventory().length-1;index++){
    for(const conclusion of ['failure','cancelled','skipped',null]){
      const jobs=inventory();jobs[index].conclusion=conclusion;assert.throws(()=>regressionStatus(jobs,contract));assert.throws(()=>requireRegressions(jobs,contract.native,contract));
    }
    const absent=inventory();absent.splice(index,1);assert.equal(regressionStatus(absent,contract),'pending');assert.throws(()=>requireRegressions(absent,contract.native,contract));
    const pending=inventory();pending[index].status='in_progress';pending[index].conclusion=null;assert.equal(regressionStatus(pending,contract),'pending');
  }
});
test('duplicates, unknown targets and changed declared inventory cannot silently weaken the release/cleanup gate',()=>{
  for(const index of [0,4,7,9,11]){const jobs=inventory();jobs.push(copy(jobs[index]));assert.throws(()=>regressionStatus(jobs,contract));}
  const foreign=inventory();foreign[0].name='native-regression / Native (foreign-target)';assert.throws(()=>regressionStatus(foreign,contract));
  for(const key of ['native','cloud','migration','migration_gate']){const c=copy(contract);c[key].pop();assert.throws(()=>validateRegressionContract(c,manifest));}
});
test('workflow runs independent fixture work before the join, and keeps Linux supplement model dependencies serial',()=>{
  const workflow=readFileSync(new URL('../../.github/workflows/release.yml',import.meta.url),'utf8');
  const part=name=>workflow.split(`\n  ${name}:\n`)[1]?.split(/\n  [a-z][\w-]*:\n/)[0];
  const migration=part('native-migration'),join=part('migration-gate'),base=part('cloud-sweep'),publish=part('publish'),ready=part('publication-ready');
  assert.match(migration,/needs: plan/);assert.doesNotMatch(migration,/needs:.*cloud-sweep|dev-smoke-gate.py|continue-on-error/);
  assert.match(migration,/dev-profile-migration-smoke.py/);assert.match(migration,/extract-artifact.mjs/);assert.match(migration,/verified-build.json/);
  assert.match(join,/needs: \[plan, cloud-sweep, native-migration\]/);assert.match(join,/base-release-sweep-/);assert.match(join,/native-profile-migration-fixture-/);
  assert.match(join,/--migration-only/);assert.match(join,/--binary-sha256 \$build.binary_sha256/);assert.match(join,/\$build.git_sha -ne \$env:CLI_SHA/);assert.match(join,/\$build.target -ne \$env:CLI_TARGET/);
  assert.doesNotMatch(base,/dev-profile-migration-smoke.py/);assert.match(base,/dev-smoke-supplements.py/);assert(base.indexOf('dev-smoke-supplements.py')<base.indexOf('dev-login-interruption-smoke.py'));
  assert.match(ready,/regressionStatus\(jobs,contract\)==='success'/);assert.doesNotMatch(ready,/native.length===4&&cloud.length===3/);assert.doesNotMatch(ready,/concurrency:|id-token:|contents: write/);assert.match(publish,/needs.publication-ready.result == 'success'/);assert.doesNotMatch(publish,/async function requireCi|async function requireRegression/);
});


test('full-validation clock includes required regressions that finish after fast-manual readiness',()=>{
  const jobs=inventory().map(j=>({...j,completed_at:'2026-10-27T00:03:00Z'}));
  jobs[0].completed_at='2026-10-27T00:08:00Z';
  jobs.find(j=>j.name==='publish').completed_at='2030-01-01T00:00:00Z';
  assert.equal(regressionCompletedAt(jobs,contract,'2026-10-27T00:05:00Z'),Date.parse('2026-10-27T00:08:00Z'));
  assert.equal(regressionCompletedAt(jobs,contract,'2026-10-27T00:09:00Z'),Date.parse('2026-10-27T00:09:00Z'));
});
test('missing, malformed, impossible or reversed required clocks never produce a full-validation duration',()=>{
  const jobs=inventory().map(j=>({...j,completed_at:'2026-10-27T00:03:00Z'}));
  for(const value of [undefined,null,'not-a-time','2026-02-31T00:00:00Z','2026-10-27T00:03:00']){
    const changed=copy(jobs);changed[0].completed_at=value;assert.equal(regressionCompletedAt(changed,contract,'2026-10-27T00:05:00Z'),null);
  }
  const reversed=copy(jobs);reversed[0].started_at='2026-10-27T00:04:00Z';assert.equal(regressionCompletedAt(reversed,contract,'2026-10-27T00:05:00Z'),null);
  assert.equal(regressionCompletedAt(jobs,contract,'not-a-time'),null);
});
