// Fixed continuation of 44292748654/1: v1.0.8 plus the unexecuted musl resident scope.
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {readFileSync,writeFileSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {api,pages,output} from './release-publication.mjs';
import {recoveryArtifact,downloadRecoveryArtifact} from './release-recovery3930.mjs';
export const muslWorkflow='.github/workflows/release-musl3930.yml';
export const muslTarget='x86_64-unknown-linux-musl';
const repo='risense-ai/respire-cli',original='44276673815',first='44292748654';
const sha='3930ba500b96a0c52eb7aa735b7ddb4117ad4e9f';
const hash=b=>createHash('sha256').update(b).digest('hex');
const fixtureFiles=['scripts/dev-legacy-vault-smoke.py','scripts/dev-migration-keyring.py','scripts/test-published-upgrades.py','scripts/test-real-m3-account-switch.py'];
// The main ancestry gate below keeps the reviewed revision unavailable until merged.
export const muslFixtureCommit='710e6b13ff588c02157d8d677e59e8f21c16beae';
export const muslFixtureBlobs={
  'scripts/dev-legacy-vault-smoke.py':'205c3df9380c00dce6e735390c569f2f1c784dc2',
  'scripts/dev-migration-keyring.py':'42a2faeb58a767445a82f3039d76ccf217ad362b',
  'scripts/test-published-upgrades.py':'da20482f5ae9e080add93fcf061c7ac96cb4709c',
  'scripts/test-real-m3-account-switch.py':'b2a40ed07da186ea6027e288bd030f396bdd8e98',
  'scripts/test-dev-credential-alias-fixtures.py':'5bf00b71a08ac3df69ce547bf7a94accae2b9e5f',
  'scripts/test-full-release-diagnostics.py':'9a68af7caaa42bc76dfa063bf2a48405162e4b9c',
  'scripts/test_published_upgrade_policy.py':'854b8d68dcc38b9e096cceb5ed4e983a8c7a29ae'};
export function fixtureIdentity(revision=process.env.MUSL_FIXTURE_COMMIT){
  assert.match(muslFixtureCommit,/^[a-f0-9]{40}$/,'Corrected fixture review and exact blob pins pending');
  assert.equal(revision,muslFixtureCommit,'Only the reviewed PR450 fixture revision is accepted');
  assert.deepEqual(Object.keys(muslFixtureBlobs).sort(),[...fixtureFiles,'scripts/test-dev-credential-alias-fixtures.py','scripts/test-full-release-diagnostics.py','scripts/test_published_upgrade_policy.py'].sort());
  execFileSync('git',['merge-base','--is-ancestor',revision,'origin/main']);
  const blobs=Object.fromEntries(Object.keys(muslFixtureBlobs).map(file=>[file,execFileSync('git',['rev-parse',`${revision}:${file}`],{encoding:'utf8'}).trim()]));
  assert.deepEqual(blobs,muslFixtureBlobs);
  assert.equal(blobs['scripts/test-published-upgrades.py'],execFileSync('git',['rev-parse','385c3c9:scripts/test-published-upgrades.py'],{encoding:'utf8'}).trim(),'Original DB report contract must remain unchanged');
  const changed=execFileSync('git',['diff','--name-only',sha,revision,'--',...fixtureFiles],{encoding:'utf8'}).trim().split(/\r?\n/);
  assert.deepEqual(changed,['scripts/dev-legacy-vault-smoke.py','scripts/test-real-m3-account-switch.py'],'Only the two reviewed diagnostic business files may change');
  return {commit:revision,files:blobs,contract:'historical-385',previous_contract:{commit:execFileSync('git',['rev-parse','385c3c9'],{encoding:'utf8'}).trim(),source_count:11}};
}
export function installFixtures(file){
  assert.equal(process.env.CLI_TARGET,muslTarget);const identity=fixtureIdentity();
  assert.equal(execFileSync('git',['rev-parse','HEAD'],{encoding:'utf8'}).trim(),sha);
  assert.equal(execFileSync('git',['-C','.recovery-harness','rev-parse','HEAD'],{encoding:'utf8'}).trim(),process.env.GITHUB_SHA);
  for(const path of fixtureFiles)writeFileSync(path,execFileSync('git',['show',`${identity.commit}:${path}`]));
  writeFileSync(file,JSON.stringify({...identity,harness_sha:process.env.GITHUB_SHA,original_sha:sha,run_id:process.env.GITHUB_RUN_ID,run_attempt:Number(process.env.GITHUB_RUN_ATTEMPT)},null,2)+'\n');
  return identity;
}
const jobs=id=>pages(`repos/${repo}/actions/runs/${id}/attempts/1/jobs?per_page=100`).flatMap(p=>p.jobs);
const artifacts=id=>pages(`repos/${repo}/actions/runs/${id}/artifacts?per_page=100`).flatMap(p=>p.artifacts);
function originalArtifact(name,jobName){
  const run=api(`repos/${repo}/actions/runs/${original}/attempts/1`);
  assert.equal(run.head_sha,sha);assert.equal(run.status,'completed');assert.equal(run.conclusion,'failure');
  assert.equal(run.path,'.github/workflows/release.yml');assert.equal(run.head_repository?.full_name,repo);
  const found=jobs(original).filter(j=>j.name===jobName);assert.equal(found.length,1);
  return recoveryArtifact(artifacts(original),name,found[0],{sha,run_id:Number(original),run_attempt:1});
}
export function validateMuslEntry(env=process.env){
  assert.equal(env.GITHUB_REPOSITORY,repo);assert.equal(env.GITHUB_REF,'refs/heads/main');assert.equal(env.GITHUB_EVENT_NAME,'workflow_dispatch');
  assert.match(env.GITHUB_SHA,/^[a-f0-9]{40}$/);assert.match(env.GITHUB_RUN_ID,/^[1-9]\d*$/);
  assert.match(env.GITHUB_RUN_ATTEMPT,/^[1-9]\d*$/);
  const consumer=api(`repos/${repo}/actions/runs/${env.GITHUB_RUN_ID}/attempts/${env.GITHUB_RUN_ATTEMPT}`);
  assert.equal(consumer.path,muslWorkflow);assert.equal(consumer.head_sha,env.GITHUB_SHA);assert.equal(consumer.head_branch,'main');
  assert.equal(consumer.event,'workflow_dispatch');assert.equal(consumer.head_repository?.full_name,repo);
  assert.equal(consumer.status,'in_progress');
  const firstRun=api(`repos/${repo}/actions/runs/${first}/attempts/1`);
  assert.equal(firstRun.path,'.github/workflows/release-recovery3930.yml');assert.equal(firstRun.head_branch,'main');
  assert.equal(firstRun.head_sha,execFileSync('git',['rev-parse','385c3c9'],{encoding:'utf8'}).trim());
  assert.equal(firstRun.head_repository?.full_name,repo);assert.ok(['in_progress','completed'].includes(firstRun.status));
  const failed=jobs(first).filter(j=>j.name===`native-regression / Native (${muslTarget})`);assert.equal(failed.length,1);
  assert.equal(failed[0].status,'completed');assert.equal(failed[0].conclusion,'failure');
  const evidence=artifacts(first).filter(a=>String(a.id)==='14424335334');assert.equal(evidence.length,1);
  assert.equal(evidence[0].digest,'sha256:23646cc75cf81d80852f752e7391994dd0751fe296a112707bfce55e458aef31');
  return {first_run:Number(first),first_attempt:1,original_run:Number(original),original_attempt:1,sha};
}
export function muslPlan(root){
  const fixture=fixtureIdentity();
  const identity=validateMuslEntry();
  const candidateArtifact=originalArtifact('candidate-assets-x86_64-unknown-linux-gnu','native-regression / Native (x86_64-unknown-linux-gnu)');
  downloadRecoveryArtifact(candidateArtifact,root);
  const candidate=JSON.parse(readFileSync(join(root,'candidate-assets-receipt.json'))).candidate;
  assert.deepEqual(candidate.source,{repository:repo,sha,version:'2.0.0-dev.19',run_id:Number(original),run_attempt:1});
  output({sha,candidate:JSON.stringify(candidate),suffix:`-musl-source-${process.env.GITHUB_RUN_ID}-${process.env.GITHUB_RUN_ATTEMPT}`});
  const receipt={diagnostic_only:true,full_passed:false,...identity,fixture,candidate_sha256:hash(JSON.stringify(candidate)),consumer:{run_id:process.env.GITHUB_RUN_ID,run_attempt:Number(process.env.GITHUB_RUN_ATTEMPT),sha:process.env.GITHUB_SHA},scope:{historical_sources:['v1.0.8'],resident:true}};
  writeFileSync(join(root,'musl-diagnostic-plan.json'),JSON.stringify(receipt,null,2)+'\n');return receipt;
}
export function muslNative(root){
  validateMuslEntry();assert.equal(process.env.CLI_TARGET,muslTarget);
  downloadRecoveryArtifact(originalArtifact('cli-release-'+muslTarget,`validate / Release (${muslTarget})`),root);
}
if(process.argv[1]&&pathToFileURL(resolve(process.argv[1])).href===import.meta.url){
  const [action,folder]=process.argv.slice(2);
  if(action==='plan')muslPlan(folder);else if(action==='native')muslNative(folder);else if(action==='fixtures')installFixtures(folder);else throw Error('Expected plan, native, or fixtures');
}
