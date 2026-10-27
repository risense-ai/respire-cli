import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync,writeFileSync,mkdtempSync,mkdirSync,cpSync,chmodSync,rmSync,existsSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {validateAcceptedScoped,validateAcceptedAlias,validateAcceptance,validateVerified,
  assertCompletedSource,acceptedScopedOutput,reconcilePriorSubmissions} from './publication-acceptance.mjs';
import {assertSourceRun,validateScoped} from './release-publication.mjs';
import {planCleanup,executeCleanup,CLEANUP_POLICY} from './cleanup-release-artifacts.mjs';
const m=JSON.parse(readFileSync(new URL('../artifact-manifest.json',import.meta.url)));
const copy=structuredClone;
const hash='a'.repeat(64), sha='b'.repeat(40), version='1.2.3-dev.4';
const source={repository:'risense-ai/respire-cli',workflow:'.github/workflows/release.yml',run_id:'100',run_attempt:'1',sha,version,channel:'dev',release_id:300};
const identity=name=>({name,version,integrity:'sha512-'+createHash('sha512').update(name).digest('base64'),shasum:'c'.repeat(40)});
const proof=p=>({...p,schema:1,state:'accepted',evidence:'npm-exit-zero',exit_code:0,signal:null,accepted_at:'2026-10-27T00:00:00Z'});
function fixture(){
  const packages=[...m.targets.map(t=>t.pkg),m.npmScope].map(identity);
  const scoped={schema:2,kind:'scoped-accepted',state:'accepted',source:copy(source),packages,acceptances:packages.map(proof),cleanup_policy:CLEANUP_POLICY,
    binaries:m.targets.map(t=>({package:t.pkg,target:t.triple,file:`rsrs-${t.triple}${t.triple.includes('windows')?'.exe':''}`,sha256:hash})),
    assets:m.targets.flatMap(t=>[`cli-build-${t.triple}.json`,`rsrs-${t.triple}-runtime.tar.gz`,`rsrs-${t.triple}${t.triple.includes('windows')?'.exe':''}`]).map(name=>({name,size:42,sha256:hash}))};
  const run={id:100,run_attempt:1,path:source.workflow,head_repository:{full_name:source.repository},head_sha:'d'.repeat(40),event:'workflow_dispatch',status:'completed',conclusion:'success',created_at:'2026-10-27T00:00:00Z',updated_at:'2026-10-27T00:10:00Z'};
  const child={...run,id:200,path:'.github/workflows/npm-alias.yml',event:'workflow_run'};
  const alias={schema:2,kind:'alias-accepted',state:'accepted',source:copy(source),scoped_packages:packages,alias:identity('rsrs-cli'),dependencies:{'@rsrsai/cli':version},publisher:{workflow:child.path,run_id:200,run_attempt:1},acceptance:proof(identity('rsrs-cli'))};
  const jobs=[{name:'publish-integrated',status:'completed',conclusion:'success',completed_at:run.updated_at}];
  const verified={schema:2,kind:'publication-verified',state:'verified',source:copy(source),packages:[...packages,alias.alias],alias_publisher:alias.publisher,
    verified_at:'2026-10-27T00:20:00Z',install:{platform:'linux-x64-gnu',version,binary_sha256:hash}};
  return {scoped,alias,run,child,jobs,verified};
}

test('accepted receipts require all exact package ACKs and cannot masquerade as verified protocol 1',()=>{
  const f=fixture();validateAcceptedScoped(f.scoped,m);
  assert.throws(()=>validateScoped(f.scoped,m));
  for(const mutate of [r=>r.acceptances.pop(),r=>r.acceptances.push(r.acceptances[0]),r=>r.acceptances[0].version='0.0.0',r=>r.acceptances[0].signal='SIGTERM',r=>r.acceptances[0].exit_code=1,r=>r.acceptances[0].evidence='submitted',r=>r.install={},r=>r.assets.pop(),r=>r.binaries[0].sha256='f'.repeat(64)]){
    const r=copy(f.scoped);mutate(r);assert.throws(()=>validateAcceptedScoped(r,m));
  }
});

test('alias ACK binds local dependency, exact source attempt and completed publisher job, without waiting for whole child workflow',()=>{
  const f=fixture();f.child.status='in_progress';f.child.conclusion=null;
  validateAcceptedAlias(f.alias,f.scoped,f.child,f.jobs);
  for(const mutate of [r=>r.source.run_attempt='2',r=>r.dependencies['@rsrsai/cli']='0.0.0',r=>r.alias.integrity='bad',r=>r.publisher.run_id=201,r=>r.install={},r=>r.acceptance.exit_code=1]){
    const r=copy(f.alias);mutate(r);assert.throws(()=>validateAcceptedAlias(r,f.scoped,f.child,f.jobs));
  }
  for(const conclusion of ['failure','cancelled','skipped',null])assert.throws(()=>validateAcceptedAlias(f.alias,f.scoped,f.child,[{...f.jobs[0],conclusion}]));
  assert.throws(()=>validateAcceptedAlias(f.alias,f.scoped,f.child,[{...f.jobs[0],status:'in_progress'}]));
});

test('completed exact attempts are allowed only in the read-only verifier, never the write guard',()=>{
  const f=fixture();assertCompletedSource(f.run,source);assert.throws(()=>assertSourceRun(f.run,source));
  assert.throws(()=>acceptedScopedOutput(f.scoped,f.run,1));
  f.run.status='in_progress';assertSourceRun(f.run,source);assert.throws(()=>assertCompletedSource(f.run,source));
  const output=acceptedScopedOutput(f.scoped,f.run,1);assert.equal(output.protocol,'2');assert.equal(output.artifact,'scoped-accepted-100-1');
  for(const mutate of [r=>r.run_attempt=2,r=>r.id=101,r=>r.conclusion='failure',r=>r.path='.github/workflows/ci.yml',r=>r.head_repository.full_name='other/repo']){
    const r=copy(fixture().run);mutate(r);assert.throws(()=>assertCompletedSource(r,source));
  }
});

test('accepted ACKs cannot replace public digest and isolated installation proof',()=>{
  const f=fixture();validateVerified(f.verified,f.scoped,f.alias);
  assert.throws(()=>validateVerified(f.alias,f.scoped,f.alias));
  for(const mutate of [r=>r.packages.pop(),r=>r.source.sha='f'.repeat(40),r=>r.alias_publisher.run_attempt=2,r=>r.install.binary_sha256='f'.repeat(64),r=>r.install.version='0.0.0',r=>r.verified_at=null]){
    const r=copy(f.verified);mutate(r);assert.throws(()=>validateVerified(r,f.scoped,f.alias));
  }
});

test('an interrupted prior submission requires read-only content reconciliation and is never replayed',async()=>{
  const p=identity('rsrs-cli'),journal={schema:2,submissions:[{state:'unknown',package:p}]};
  let reads=0;const recovered=await reconcilePriorSubmissions(journal,[p],async items=>{reads++;assert.deepEqual(items,[p]);});assert.equal(reads,1);assert.equal(recovered[0].evidence,'verified-public-bytes');
  await assert.rejects(reconcilePriorSubmissions(journal,[p],async()=>{throw Error('not publicly confirmed; no retry');}),/no retry/);
  await assert.rejects(reconcilePriorSubmissions(journal,[{...p,shasum:'e'.repeat(40)}]),/content changed/);
  journal.submissions[0]={state:'accepted',package:proof(p)};const existing=await reconcilePriorSubmissions(journal,[p],async()=>assert.fail('accepted submission does not need propagation'));assert.deepEqual(existing,[proof(p)]);
  validateAcceptance(proof(p),p);
});

function cleanupFixture(){
  const f=fixture(),last='2026-10-27T00:20:00Z';
  const verifier={...f.run,id:400,path:'.github/workflows/verify-publication.yml',event:'workflow_run',updated_at:last};
  const a=(id,name,run)=>({id,name,expired:false,digest:'sha256:'+hash,size_in_bytes:100,created_at:'2026-10-27T00:10:00Z',workflow_run:{id:run.id,head_sha:run.head_sha}});
  f.verifiers=[verifier];f.consumers=[f.child];f.deleted=[];
  f.artifacts=new Map([[10,a(10,'cli-release-'+m.targets[0].triple,f.run)],[11,a(11,'scoped-accepted-100-1',f.run)],[12,a(12,'alias-accepted-100-1-200-1',f.child)],[13,a(13,'publication-verified-100-1-400-1',verifier)]]);
  const job=name=>({name,status:'completed',conclusion:'success',completed_at:f.run.updated_at});
  f.parentJobs=[...m.targets.map(t=>job(`native-regression / Native (${t.triple})`)),...m.targets.filter(t=>t.triple!=='x86_64-unknown-linux-gnu').map(t=>job(`cloud-sweep (${t.triple})`)),job('api-smoke'),job('publish')];
  f.io={repository:source.repository,run:async()=>copy(f.run),artifacts:async id=>copy([...f.artifacts.values()].filter(a=>a.workflow_run.id===id)),
    receipt:async a=>copy(a.id===11?f.scoped:a.id===12?f.alias:f.verified),jobs:async id=>copy(id===100?f.parentJobs:id===200?f.jobs:[job('verify-publication')]),
    release:async()=>({id:300,draft:false,published_at:f.run.updated_at,tag_name:'v'+version,target_commitish:sha,prerelease:true,assets:f.scoped.assets.map(a=>({...a,state:'uploaded',digest:'sha256:'+a.sha256}))}),tag:async()=>({type:'commit',sha}),
    consumers:async()=>copy(f.consumers),verifiers:async()=>copy(f.verifiers),artifact:async id=>copy(f.artifacts.get(id)??null),deleteArtifact:async id=>{f.deleted.push(id);f.artifacts.delete(id);}};
  return f;
}

test('cleanup waits for verified proof and the last background consumer/report plus an hour',async()=>{
  const f=cleanupFixture(),at=Date.parse('2026-10-27T01:20:00Z');
  f.artifacts.delete(13);assert.equal((await planCleanup(f.io,100,m,at)).skip,'no-completed-public-install-proof');assert.deepEqual(f.deleted,[]);
  const complete=cleanupFixture();assert.equal((await planCleanup(complete.io,100,m,at-1)).skip,'one-hour-after-consumers-not-reached');
  const plan=await planCleanup(complete.io,100,m,at);assert.equal(plan.skip,undefined);assert.deepEqual(plan.artifacts.map(a=>a.id),[10,12,13,11]);
  await executeCleanup(complete.io,plan,{apply:true,now:()=>at});assert.deepEqual(complete.deleted,[10,12,13,11]);
});

test('active/new background consumers, failed verification and digest drift stop cleanup',async()=>{
  const at=Date.parse('2026-10-27T02:00:00Z');
  const active=cleanupFixture();active.verifiers[0].status='in_progress';assert.equal((await planCleanup(active.io,100,m,at)).skip,'public-verification-still-active');
  const failed=cleanupFixture();failed.verifiers[0].conclusion='failure';await assert.rejects(planCleanup(failed.io,100,m,at),/failed/);
  const bad=cleanupFixture();bad.verified.install.binary_sha256='f'.repeat(64);await assert.rejects(planCleanup(bad.io,100,m,at),/verification/);
  const late=cleanupFixture(),plan=await planCleanup(late.io,100,m,at);late.verifiers.push({...late.verifiers[0],id:401,status:'queued'});
  await assert.rejects(executeCleanup(late.io,plan,{apply:true,now:()=>at}),/fence changed/);assert.deepEqual(late.deleted,[]);
});

test('new background workflow is read-only, outside publication locks and behind Release completion',()=>{
  const root=new URL('../../',import.meta.url),text=p=>readFileSync(new URL(p,root),'utf8');
  const background=text('.github/workflows/verify-publication.yml'),parent=text('.github/workflows/release.yml').split('  dev6-publication-resume:')[0];
  assert.match(background,/types: \[completed\]/);assert.match(background,/workflow_run.conclusion == 'success'/);
  assert.doesNotMatch(background,/id-token:|contents: write|actions: write|concurrency:|npm publish/);
  assert.match(background,/persist-credentials: false/);assert.match(background,/verify-accepted/);
  assert.match(parent,/--publish --accepted-only --tag/);assert.match(parent,/await-alias-accepted/);assert.match(parent,/finalize-accepted/);
  assert.doesNotMatch(parent,/release-publication.mjs (?:scoped-ready|await-alias\s|finalize\s)/);
  const code=text('npm/scripts/publication-acceptance.mjs');
  const writer=code.slice(code.indexOf('async function publishAliasAccepted'),code.indexOf('export async function findAcceptedAlias'));
  assert.doesNotMatch(writer,/publicInstall\(|verifyPackages\(scoped.packages|result.metadata/);
  assert.match(writer,/assertActive\(source\); \/\/ No public propagation/);
  assert.match(code,/actions\/runs\/\$\{runId\}\/attempts\/\$\{attempt\}/);
});

test('real coordinator processes finish acceptance while child workflow runs, and stale attempts never edit Release',t=>{
  const root=mkdtempSync(path.join(tmpdir(),'rsrs-accepted-process-'));t.after(()=>rmSync(root,{recursive:true,force:true}));
  mkdirSync(path.join(root,'bin'));mkdirSync(path.join(root,'npm'));
  cpSync(fileURLToPath(new URL('.',import.meta.url)),path.join(root,'npm/scripts'),{recursive:true});
  writeFileSync(path.join(root,'npm/artifact-manifest.json'),JSON.stringify(m));
  const f=fixture();f.run.status='in_progress';f.run.conclusion=null;f.child.status='in_progress';f.child.conclusion=null;
  const release={id:300,draft:true,prerelease:true,tag_name:'v'+version,target_commitish:sha,assets:f.scoped.assets.map(a=>({...a,state:'uploaded',digest:'sha256:'+a.sha256}))};
  const save=()=>writeFileSync(path.join(root,'fixture.json'),JSON.stringify({...f,release}));save();
  writeFileSync(path.join(root,'scoped-accepted.json'),JSON.stringify(f.scoped));
  const gh=path.join(root,'bin/gh');
  writeFileSync(gh,`#!${process.execPath}
const fs=require('fs'),path=require('path'),args=process.argv.slice(2),f=JSON.parse(fs.readFileSync('fixture.json'));
const pub=()=>fs.existsSync('edited-release');
function out(x){process.stdout.write(JSON.stringify(x));}
if(args[0]==='api'){
 const endpoint=args.at(-1),paginated=args.includes('--slurp');
 let value;
 if(endpoint.endsWith('/actions/runs/100'))value=f.run;
 else if(endpoint.endsWith('/actions/runs/200/attempts/1'))value=f.child;
 else if(endpoint.includes('/workflows/npm-alias.yml/runs?'))value={workflow_runs:[f.child]};
 else if(endpoint.includes('/actions/runs/200/attempts/1/jobs?'))value={jobs:f.jobs};
 else if(endpoint.includes('/actions/runs/200/artifacts?'))value={artifacts:[{name:'alias-accepted-100-1-200-1',expired:false,workflow_run:{id:200}}]};
 else if(endpoint.endsWith('/releases/300'))value=pub()?{...f.release,draft:false,published_at:'2026-10-27T00:10:00Z'}:f.release;
 else if(endpoint.includes('/git/ref/tags/'))value={object:{type:'commit',sha:f.scoped.source.sha}};
 else throw Error('Unpermitted fake API '+endpoint);
 out(paginated?[value]:value);
}else if(args[0]==='run'&&args[1]==='download'){
 const dir=args[args.indexOf('--dir')+1];fs.writeFileSync(path.join(dir,'alias-accepted.json'),JSON.stringify(f.alias));
}else if(args[0]==='release'&&args[1]==='edit'){
 if(pub())throw Error('Release edit must never replay');
 fs.writeFileSync('edited-release',JSON.stringify(args));
}else throw Error('Unpermitted fake command '+args.join(' '));
`);chmodSync(gh,0o755);
  const bootstrap=path.join(root,'run.mjs');writeFileSync(bootstrap,`globalThis.fetch=()=>{throw Error('Accepted barrier must not wait on public registry');};
const {main}=await import('./npm/scripts/release-publication.mjs');
main(process.argv[2]).catch(e=>{console.error(e.message);process.exitCode=1;});`);
  const env={...process.env,PATH:path.join(root,'bin')+path.delimiter+process.env.PATH,GITHUB_REPOSITORY:source.repository,GITHUB_RUN_ID:'100',GITHUB_RUN_ATTEMPT:'1'};
  const run=action=>spawnSync(process.execPath,[bootstrap,action],{cwd:root,env,encoding:'utf8',timeout:15000});
  const awaited=run('await-alias-accepted');assert.equal(awaited.error,undefined);assert.equal(awaited.status,0,awaited.stderr);
  const complete=JSON.parse(readFileSync(path.join(root,'publication-accepted.json')));assert.equal(complete.state,'accepted');assert.equal(complete.alias_run,200);assert.equal(complete.alias_receipt.install,undefined);
  f.run.status='completed';save();const stale=run('finalize-accepted');assert.notEqual(stale.status,0);assert.match(stale.stderr,/stale|inactive/);assert.equal(existsSync(path.join(root,'edited-release')),false);
  f.run.status='in_progress';save();const finalized=run('finalize-accepted');assert.equal(finalized.status,0,finalized.stderr);assert.equal(existsSync(path.join(root,'edited-release')),true);
  const summary=JSON.parse(readFileSync(path.join(root,'publication-accepted.json')));assert.equal(summary.public_verification,'pending');assert.equal(summary.trigger_to_accepted_seconds,600);
});
