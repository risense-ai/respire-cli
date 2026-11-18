// One recovery for CLI3930/run44276673815; producer bytes and original evidence stay immutable.
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {mkdirSync,mkdtempSync,readFileSync,writeFileSync,rmSync,copyFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {api,pages,output} from './release-publication.mjs';
import {validateCandidate,completeCandidate} from './candidate-artifact.mjs';
import {preparationInputs,preparedAssets,preparedPacks,createPreparation,validatePreparationHistory,validatePreparationFull} from './release-preparation.mjs';
import {readFence} from './publication-fence.mjs';

export const recoveryWorkflow='.github/workflows/release-recovery3930.yml';
export const windowsTarget='x86_64-pc-windows-msvc';
const REPO='risense-ai/respire-cli',positive=n=>Number.isSafeInteger(Number(n))&&/^[1-9]\d*$/.test(String(n));
const hash=b=>createHash('sha256').update(b).digest('hex');
const PRODUCT='3930ba500b96a0c52eb7aa735b7ddb4117ad4e9f',BUILD_RUN='44276673815';
const suffix=s=>`-recovery-${s.run_id}-${s.run_attempt}`;
const retryable=j=>j.name.startsWith('native-regression / Native (')||j.name.startsWith('cloud-sweep (');
const targetOf=j=>j.name.startsWith('native-regression')?j.name.match(/Native \(([^)]+)\)$/)[1]:j.name.match(/, ([^)]+)\)$/)[1];
const osFor=t=>t.includes('windows')?(t.startsWith('aarch64')?'windows-11-arm':'windows-latest'):t.includes('darwin')?(t.startsWith('aarch64')?'macos-15':'macos-15-intel'):(t.startsWith('aarch64')?'ubuntu-24.04-arm':'ubuntu-latest');
const readJobs=s=>pages(`repos/${REPO}/actions/runs/${s.run_id}/attempts/${s.run_attempt}/jobs?per_page=100`).flatMap(p=>p.jobs);
const readArtifacts=s=>pages(`repos/${REPO}/actions/runs/${s.run_id}/artifacts?per_page=100`).flatMap(p=>p.artifacts);
const originOwner=s=>({sha:s.sha,run_id:Number(s.run_id),run_attempt:Number(s.run_attempt)});
export function cloudScope(original,recovery){
  const tail=text=>{
    const marker='      - name: Bind fixtures to an independent official pinned Runtime\n',start=text.indexOf(marker);
    assert.ok(start>=0,'Missing original cloud execution scope');
    return text.slice(start).split(/\n  (?:api-smoke|preparation-receipt):/)[0].trimEnd();
  };
  const before=tail(original.replace(/\r\n/g,'\n'));
  const expected=before.replace(/inputs\.artifact_source == 'published-assets' && needs\.artifact-inputs\.outputs\.(sha|version) \|\| needs\.plan\.outputs\.\1/g,(_,key)=>'needs.plan.outputs.'+key)
    .replaceAll("inputs.artifact_source != 'published-assets'",'true').replaceAll("inputs.artifact_source == 'published-assets'",'false').replaceAll('        if: true\n','');
  assert.equal(tail(recovery.replace(/\r\n/g,'\n')).replaceAll('${{ needs.plan.outputs.suffix }}',''),expected,'Cloud scope, environment or commands changed');
  return hash(before);
}

export function validateRecoveryRuns(producerRun,consumerRun,producer,consumer){
  for(const [run,s,path] of [[producerRun,producer,'.github/workflows/release.yml'],[consumerRun,consumer,recoveryWorkflow]]){
    assert.ok(positive(s.run_id)&&positive(s.run_attempt));
    assert.equal(run.id,Number(s.run_id));assert.equal(run.run_attempt,Number(s.run_attempt));
    assert.equal(run.head_repository?.full_name,REPO);assert.equal(run.path,path);
    assert.equal(run.event,'workflow_dispatch');assert.equal(run.head_branch,'main');
    assert.equal(run.head_sha,s.workflow_head_sha || s.sha);
  }
  assert.notEqual(Number(producer.run_id),Number(consumer.run_id));
  assert.equal(producerRun.status,'completed');assert.equal(producerRun.conclusion,'failure');
  assert.ok(['in_progress','completed'].includes(consumerRun.status));
  if(consumerRun.status==='completed')assert.equal(consumerRun.conclusion,'success');
  assert.equal(producer.sha,consumer.sha);assert.equal(producer.version,consumer.version);
}

// A continuation may change only this CI implementation and its existing checks.
// All product files, fixture scripts, locks, model keys and other workflows must be identical.
export function recoveryScripts(producerSHA,consumerSHA,{cwd=process.cwd()}={}){
  const allowed=new Set([recoveryWorkflow,'.github/workflows/release-native-validation.yml','.github/workflows/release.yml','.github/workflows/npm-alias.yml','.github/workflows/ci.yml',
    'npm/scripts/release-recovery3930.mjs','npm/scripts/release-preparation.mjs','npm/scripts/candidate-artifact.mjs',
    'npm/scripts/extract-artifact.mjs','npm/scripts/test-release-preparation.mjs',
    'npm/scripts/test-release-regression-contract.mjs','npm/scripts/test-publication-acceptance.mjs',
    'npm/scripts/publication-acceptance.mjs','npm/scripts/release-publication.mjs','npm/scripts/cleanup-release-artifacts.mjs','scripts/create-published-assets.mjs','scripts/test-native-runtime-install.py']);
  execFileSync('git',['merge-base','--is-ancestor',producerSHA,consumerSHA],{cwd});
  const changed=execFileSync('git',['diff','--name-only',producerSHA,consumerSHA],{cwd,encoding:'utf8'}).trim().split(/\r?\n/).filter(Boolean);
  assert.ok(changed.every(file=>allowed.has(file)),'Product, fixture or unrelated CI source changed since producer');
  const nativeTail=sha=>{
    const text=execFileSync('git',['show',`${sha}:.github/workflows/release-native-validation.yml`],{cwd,encoding:'utf8'}).replace(/\r\n/g,'\n');
    const start=text.indexOf('      - name: Verify and extract the release binary\n');assert.ok(start>=0,'Missing original native entry');
    return text.slice(start);
  };
  const originalSteps=nativeTail(producerSHA);assert.equal(nativeTail(consumerSHA).replaceAll('${{ inputs.recovery_suffix }}',''),originalSteps,'Windows native scope or commands changed');
  const show=(sha,file)=>execFileSync('git',['show',`${sha}:${file}`],{cwd,encoding:'utf8'});
  const cloud_steps_sha256=cloudScope(show(producerSHA,'.github/workflows/release.yml'),show(consumerSHA,recoveryWorkflow));
  const tree=execFileSync('git',['ls-tree','-r',producerSHA],{cwd,encoding:'utf8',maxBuffer:16*1024*1024});
  return {producer_sha:producerSHA,consumer_sha:consumerSHA,native_steps_sha256:hash(originalSteps),cloud_steps_sha256,
    // Keep the original 385 receipt digest definition as orchestration readers grow.
    unchanged_tree_sha256:hash(tree.split('\n').filter(line=>!allowed.has(line.split('\t')[1])||['npm/scripts/publication-acceptance.mjs','npm/scripts/release-publication.mjs','npm/scripts/cleanup-release-artifacts.mjs','scripts/create-published-assets.mjs'].includes(line.split('\t')[1])).join('\n'))};
}

export function recoveryJobs(original,current,producer,consumer,manifest,{planning=false}={}){
  for(const j of original.filter(retryable))assert.ok(manifest.targets.some(t=>t.triple===targetOf(j))&&(!j.name.startsWith('cloud-sweep (')||targetOf(j)!=='x86_64-unknown-linux-gnu'),'Unknown recovery scope');
  const failed=original.filter(j=>retryable(j)&&j.conclusion==='failure');assert.ok(failed.length,'No failed native/cloud job');
  const failedNames=new Set(failed.map(j=>j.name));
  for(const j of failed){assert.ok(positive(j.id));assert.equal(j.status,'completed');assert.equal(j.run_id,Number(producer.run_id));assert.equal(j.run_attempt,Number(producer.run_attempt));assert.equal(j.head_sha,producer.sha);}
  const reused=original.filter(j=>j.name.startsWith('validate / Release (')||j.name==='validate / npm-dry-run'||j.name==='api-smoke'||
    retryable(j)&&!failedNames.has(j.name));
  const replacements=current.filter(retryable);
  assert.equal(replacements.length,planning?0:failed.length,'Require exactly the failed native/cloud scopes');
  assert.ok(replacements.every(j=>failedNames.has(j.name)),'Successful scope must not rerun');
  const owners={};
  for(const [jobs,s] of [[reused,originOwner(producer)],[replacements,{...originOwner(consumer),sha:consumer.workflow_head_sha}]]){
    for(const j of jobs){
      assert.ok(positive(j.id));assert.equal(j.run_id,s.run_id);assert.equal(j.run_attempt,s.run_attempt);assert.equal(j.head_sha,s.sha);
      assert.equal(j.status,'completed');assert.equal(j.conclusion,'success');
      assert.equal(owners[j.name],undefined,'Duplicate evidence owner');owners[j.name]=s;
    }
  }
  const required=[...manifest.targets.map(t=>`validate / Release (${t.triple})`),'validate / npm-dry-run','api-smoke',
    ...manifest.targets.map(t=>`native-regression / Native (${t.triple})`),
    ...manifest.targets.filter(t=>t.triple!=='x86_64-unknown-linux-gnu').map(t=>t.triple)];
  const joined=[...reused,...replacements];
  assert.equal(joined.length,required.length-(planning?failed.length:0),'Unexpected required job inventory');
  for(const name of required){
    if(planning&&(failedNames.has(name)||failed.some(j=>j.name.startsWith('cloud-sweep (')&&targetOf(j)===name)))continue;
    assert.equal(joined.filter(j=>j.name===name||j.name.startsWith('cloud-sweep (')&&j.name.endsWith(', '+name+')')).length,1,'Missing full evidence: '+name);
  }
  return {jobs:[...joined,...current.filter(j=>j.name==='preparation-receipt')],evidenceOwners:owners};
}

export function recoveryArtifact(artifacts,name,job,owner,{failed=false}={}){
  assert.equal(job.status,'completed');assert.equal(job.conclusion,failed?'failure':'success');
  assert.equal(job.run_id,Number(owner.run_id));assert.equal(job.run_attempt,Number(owner.run_attempt));assert.equal(job.head_sha,owner.sha);
  const found=artifacts.filter(a=>a.name===name);assert.equal(found.length,1,'Missing or duplicate artifact: '+name);
  const a=found[0];
  assert.ok(positive(a.id)&&positive(a.size_in_bytes));assert.equal(a.expired,false);assert.match(a.digest,/^sha256:[a-f0-9]{64}$/);
  assert.equal(a.workflow_run?.id,Number(owner.run_id));assert.equal(a.workflow_run.head_sha,owner.sha);
  const times=[job.started_at,a.created_at,a.updated_at,job.completed_at].map(Date.parse);
  assert.ok(times.every(Number.isFinite)&&times.every((n,i)=>i===0||n>=times[i-1]),'Artifact does not belong to the selected producer job/attempt');
  return {id:String(a.id),name:a.name,size:a.size_in_bytes,digest:a.digest,job_id:job.id,owner,conclusion:job.conclusion};
}

// Download through gh, check the original ZIP digest, then extract regular files only.
export function downloadRecoveryArtifact(a,destination,{transport=execFileSync}={}){
  if(transport===execFileSync)assert.ok(process.env.GH_TOKEN,'Explicit read token required');
  const bytes=transport('gh',['api','--hostname','github.com',`repos/${REPO}/actions/artifacts/${a.id}/zip`],{maxBuffer:1024*1024*1024});
  assert.equal(bytes.length,a.size);assert.equal('sha256:'+hash(bytes),a.digest,'Original artifact ZIP digest differs');
  mkdirSync(destination,{recursive:true});const zip=join(destination,'.download.zip');writeFileSync(zip,bytes);
  try{execFileSync(process.platform==='win32'?'py':'python3',[...(process.platform==='win32'?['-3']:[]),'-I','-c',`
import pathlib,stat,sys,zipfile
root=pathlib.Path(sys.argv[2]).resolve()
with zipfile.ZipFile(sys.argv[1]) as z:
 names=z.namelist(); assert len(names)==len(set(names)), 'Duplicate ZIP members'
 assert sum(e.file_size for e in z.infolist()) <= 1024**3, 'Oversized ZIP payload'
 for e in z.infolist():
  p=pathlib.PurePosixPath(e.filename)
  assert not p.is_absolute() and '..' not in p.parts and '\\\\' not in e.filename and ':' not in e.filename, 'Unsafe ZIP path'
  assert stat.S_IFMT(e.external_attr>>16) in (0,stat.S_IFREG,stat.S_IFDIR), 'Non-regular ZIP entry'
  target=root.joinpath(*p.parts).resolve(); assert target.is_relative_to(root) and target!=root, 'Escaped ZIP member'
  if e.is_dir(): target.mkdir(parents=True,exist_ok=True); continue
  target.parent.mkdir(parents=True,exist_ok=True)
  with target.open('xb') as out: out.write(z.read(e))
`,zip,destination],{stdio:'inherit'});}finally{rmSync(zip);}
}

function currentSource(producer){
  assert.equal(process.env.GITHUB_REPOSITORY,REPO);assert.equal(process.env.GITHUB_EVENT_NAME,'workflow_dispatch');assert.equal(process.env.GITHUB_REF,'refs/heads/main');
  assert.match(process.env.GITHUB_SHA,/^[a-f0-9]{40}$/);
  assert.equal(execFileSync('git',['rev-parse','HEAD'],{encoding:'utf8'}).trim(),PRODUCT);
  assert.equal(execFileSync('git',['-C','.recovery-harness','rev-parse','HEAD'],{encoding:'utf8'}).trim(),process.env.GITHUB_SHA);
  return {repository:REPO,workflow:recoveryWorkflow,run_id:process.env.GITHUB_RUN_ID,run_attempt:Number(process.env.GITHUB_RUN_ATTEMPT),
    sha:producer.sha,version:producer.version,workflow_head_sha:process.env.GITHUB_SHA,producer};
}
export function recoveryContext(source,{planning=false}={}){
  const producer=source.producer;
  assert.equal(producer.sha,PRODUCT);assert.equal(String(producer.run_id),BUILD_RUN);assert.equal(producer.run_attempt,1);assert.equal(producer.version,'2.0.0-dev.19');
  const producerRun=api(`repos/${REPO}/actions/runs/${producer.run_id}`),run=api(`repos/${REPO}/actions/runs/${source.run_id}`);
  validateRecoveryRuns(producerRun,run,producer,source);
  const scripts=recoveryScripts(producer.sha,source.workflow_head_sha);
  const inputs=preparationInputs(producer.sha,producer.version),original=readJobs(producer),current=readJobs(source);
  const joined=recoveryJobs(original,planning?[]:current,producer,source,inputs.manifest,{planning});
  const artifacts=readArtifacts(producer),consumerArtifacts=readArtifacts(source);
  const candidates=pages(`repos/${REPO}/actions/workflows/ci.yml/runs?head_sha=${source.sha}&per_page=100`).flatMap(p=>p.workflow_runs)
    .filter(r=>r.head_sha===source.sha&&r.event==='push'&&r.head_branch==='main').sort((a,b)=>b.id-a.id);
  assert.ok(candidates.length);const ci=api(`repos/${REPO}/actions/runs/${candidates[0].id}`);
  assert.equal(ci.id,candidates[0].id);assert.ok(positive(ci.run_attempt));assert.equal(ci.path,'.github/workflows/ci.yml');
  assert.equal(ci.head_sha,source.sha);assert.equal(ci.head_branch,'main');assert.equal(ci.event,'push');assert.equal(ci.head_repository?.full_name,REPO);
  assert.equal(ci.status,'completed');assert.equal(ci.conclusion,'success');
  return {...inputs,source,run,ci,...joined,artifacts,consumerArtifacts,original,current,scripts};
}

function select(context,name,jobName,replacement=false){
  const s=replacement?{...originOwner(context.source),sha:context.source.workflow_head_sha}:originOwner(context.source.producer);
  const jobs=(replacement?context.current:context.original).filter(j=>j.name===jobName);assert.equal(jobs.length,1);
  return {...recoveryArtifact(replacement?context.consumerArtifacts:context.artifacts,replacement?name+suffix(context.source):name,jobs[0],s),logical_name:name};
}
export function recoveryArtifacts(context){
  const anchors=[],take=(...args)=>anchors.push(select(context,...args));
  for(const {triple:target} of context.manifest.targets){
    take('cli-release-'+target,`validate / Release (${target})`);
    const native=`native-regression / Native (${target})`,replace=context.original.find(j=>j.name===native)?.conclusion==='failure';
    for(const prefix of ['candidate-assets-','resident-concurrency-','published-upgrades-'])take(prefix+target,native,replace);
    if(target===windowsTarget)take('client2-published-online-'+target,native,replace);
    if(target==='x86_64-unknown-linux-gnu'){take('gnu-login-interruption',native,replace);continue;}
    const cloud=context.original.filter(j=>j.name.startsWith('cloud-sweep (')&&j.name.endsWith(', '+target+')'));assert.equal(cloud.length,1);
    take('base-release-sweep-'+target,cloud[0].name,cloud[0].conclusion==='failure');
    if(target.includes('linux'))for(const prefix of ['release-sweep-','secret-service-profile-migration-'])take(prefix+target,cloud[0].name,cloud[0].conclusion==='failure');
  }
  for(const name of ['npm-release-validation','npm-release-packages'])take(name,'validate / npm-dry-run');
  take('dev-api-coverage','api-smoke');
  return anchors;
}
function failedArtifacts(context){
  const owner=originOwner(context.source.producer),out=[];
  for(const job of context.original.filter(j=>retryable(j)&&j.conclusion==='failure')){
    const t=targetOf(job),names=job.name.startsWith('native')?['candidate-assets-'+t,'resident-concurrency-'+t,'published-upgrades-'+t,...(t===windowsTarget?['client2-published-online-'+t]:[]),...(t==='x86_64-unknown-linux-gnu'?['gnu-login-interruption']:[])]:['base-release-sweep-'+t,'release-sweep-'+t,'secret-service-profile-migration-'+t];
    for(const name of names.filter(n=>context.artifacts.some(a=>a.name===n)))out.push({...recoveryArtifact(context.artifacts,name,job,owner,{failed:true}),reused:false});
  }return out;
}
export function validateRecoveryEvidence(result,context){
  const c=result.continuation,s=context.source;
  assert.deepEqual(c?.producer,s.producer);
  assert.deepEqual(c.consumer,{run_id:s.run_id,run_attempt:s.run_attempt,sha:s.workflow_head_sha});
  assert.deepEqual(c.scripts,context.scripts);
  assert.deepEqual(c.artifacts,recoveryArtifacts(context));
  assert.deepEqual(c.failed_artifacts,failedArtifacts(context));
  assert.deepEqual(c.failed_jobs,context.original.filter(j=>retryable(j)&&j.conclusion==='failure').map(j=>({id:j.id,name:j.name,run_attempt:j.run_attempt})));
  assert.ok(result.reports.every(r=>c.artifacts.some(a=>a.logical_name===r.artifact)),'Unbound full report');
}
function readCandidate(context,root){
  const target='x86_64-unknown-linux-gnu',name='candidate-assets-'+target;
  downloadRecoveryArtifact(select(context,name,`native-regression / Native (${target})`),join(root,name));
  const c=JSON.parse(readFileSync(join(root,name,'candidate-assets-receipt.json'))).candidate,p=context.source.producer;
  validateCandidate(c,{CLI_SHA:p.sha,CLI_VERSION:p.version,GITHUB_RUN_ID:p.run_id,GITHUB_RUN_ATTEMPT:p.run_attempt,GITHUB_SHA:p.sha});
  assert.equal(c.source.repository,p.repository);return c;
}
function requestedProducer(){
  return {repository:REPO,workflow:'.github/workflows/release.yml',run_id:BUILD_RUN,run_attempt:1,sha:PRODUCT,version:'2.0.0-dev.19'};
}
// Release notes preserve this attestation after temporary Actions artifacts expire.
const publicPrefix='<!-- rsrs-cli3930-recovery:';
export const recoveryProofName='cli3930-recovery-proof.json';
export function readPublicationCandidate(imported){
  const root=mkdtempSync(join(tmpdir(),'recovery-public-candidate-'));
  try{return readCandidate(imported.history,root);}finally{rmSync(root,{recursive:true});}
}
export function recoveryPublicationEvidence(imported,candidate){
  const receipt=imported.receipt.preparation;
  validatePreparationHistory(receipt,imported.history);
  const evidence={candidate,acceptance:publicRecoveryResult(receipt.full_result)};
  const c=evidence.candidate,pick=(v,keys)=>Object.fromEntries(keys.map(k=>[k,v[k]]));
  const safe={...pick(c,['schema','kind']),client2:pick(c.client2,['release','source_sha']),source:pick(c.source,['repository','sha','version','run_id','run_attempt']),
    runtime:{...pick(c.runtime,['repository','release_id','version','source_sha']),producer:pick(c.runtime.producer,['run_id','run_attempt']),assets:c.runtime.assets.map(a=>pick(a,['id','name','size','sha256']))}};
  assert.deepEqual(c,safe,'Unknown candidate field');
  validateCandidate(c,{CLI_SHA:PRODUCT,CLI_VERSION:'2.0.0-dev.19',GITHUB_RUN_ID:BUILD_RUN,GITHUB_RUN_ATTEMPT:1,GITHUB_SHA:PRODUCT});
  assert.equal(hash(JSON.stringify(evidence.candidate)),receipt.full_result.manifest_sha256,'Candidate preimage differs');
  // Publish a whitelist projection; the original schema1 receipt stays private and unchanged.
  assert.deepEqual(publicRecoveryResult(evidence.acceptance),evidence.acceptance,'Unsafe recovery result');
  return Buffer.from(JSON.stringify(evidence));
}
function publicRecoveryResult(result){
  const pick=(v,keys)=>Object.fromEntries(keys.map(k=>[k,v[k]]));
  const hashes=p=>Object.fromEntries(['manifest_sha256','bundle_sha256','image_sha256'].map(k=>{assert.match(p[k],/^[a-f0-9]{64}$/);return [k,p[k]];}));
  const {actual_processes,limits,...rest}=result;
  assert.ok(Object.keys(rest).every(k=>['schema','scope','profile_import','kind','manifest_sha256','harness_sha','product_sources','sha','run_id','run_attempt','reports','historical_upgrades','full_passed','gui_passed','g1Passed','continuation'].includes(k)),'Unknown full-result field');
  const files=new Set(['candidate-assets-receipt.json','real-account-return-verification.json','resident-stress-metrics.json','fixture-dependencies.json','fixture-process-verification.json','published-upgrades.json','coverage.json','combined-coverage.json','suite-results.json','ai-inject-coverage.json','legacy-vault-coverage.json','interruption-coverage.json','outbox-coverage.json','runtime-coverage.json','source-version.json','report.json','published-api-identity.json','dev-api-coverage.json','dev-github-api-coverage.json']);
  for(const r of rest.reports){
    assert.ok(r.path.split('/').every((s,i,a)=>i===a.length-1?files.has(s):['resident-concurrency','native-fixture-bounds','published-upgrades','release-supplements','release-sweep','results','outbox','ai-inject','runtime','legacy-vault','login-interruption'].includes(s)||/^v\d+\.\d+\.\d+(?:-dev\.\d+)?$/.test(s)),'Non-whitelisted report path');
    assert.deepEqual(Object.keys(r).sort(),['artifact','path','sha256']);assert.match(r.sha256,/^[a-f0-9]{64}$/);
  }
  rest.profile_import=pick(rest.profile_import,['required','status','diagnostic_workflow']);
  rest.product_sources=pick(rest.product_sources,['cli','runtime']);
  rest.historical_upgrades=rest.historical_upgrades.map(r=>{
    for(const tag of [...r.passed,...r.not_applicable])assert.match(tag,/^v\d+\.\d+\.\d+(?:-dev\.\d+)?$/);
    return pick(r,['target','profile','all_published_sources_covered','passed','not_applicable']);
  });
  const c=rest.continuation,anchor=a=>({...pick(a,['id','name','size','digest','job_id','conclusion']),owner:pick(a.owner,['sha','run_id','run_attempt']),
    ...(a.logical_name?{logical_name:a.logical_name}:{}),...(a.reused===false?{reused:false}:{})});
  rest.continuation={producer:pick(c.producer,['repository','workflow','run_id','run_attempt','sha','version']),consumer:pick(c.consumer,['run_id','run_attempt','sha']),
    scripts:pick(c.scripts,['producer_sha','consumer_sha','native_steps_sha256','cloud_steps_sha256','unchanged_tree_sha256']),
    artifacts:c.artifacts.map(anchor),failed_artifacts:c.failed_artifacts.map(anchor),failed_jobs:c.failed_jobs.map(j=>pick(j,['id','name','run_attempt']))};
  return {...rest,actual_processes:actual_processes.map(hashes)};
}
export function recoveryPublicationBody(body,imported,publisher,candidate){
  const receipt=imported.receipt.preparation;
  assert.deepEqual(receipt.source.producer,requestedProducer());
  validatePreparationHistory(receipt,imported.history);
  assert.equal(receipt.validation_profile,'full');assert.equal(receipt.full_result.full_passed,true);
  assert.equal(publisher.sha,PRODUCT);assert.equal(publisher.version,receipt.source.version);
  const fence=readFence(body);
  assert.equal(String(fence?.run_id),String(publisher.run_id));assert.equal(fence.source_sha,PRODUCT);assert.equal(fence.phase,'fenced');
  assert.equal(fence.version,publisher.version);
  const pick=(v,keys)=>Object.fromEntries(keys.map(k=>[k,v[k]]));
  const proof={schema:1,source:{...pick(receipt.source,['repository','workflow','run_id','run_attempt','sha','version','workflow_head_sha']),producer:requestedProducer()},
    publisher:pick(publisher,['repository','workflow','run_id','run_attempt','sha','version','release_id','workflow_head_sha']),assets:receipt.assets.map(a=>pick(a,['file','size','sha256'])),
    manifest_sha256:receipt.full_result.manifest_sha256,acceptance_sha256:hash(JSON.stringify(publicRecoveryResult(receipt.full_result))),
    scripts:receipt.full_result.continuation.scripts};
  const evidence=recoveryPublicationEvidence(imported,candidate);
  proof.evidence={name:recoveryProofName,size:evidence.length,sha256:hash(evidence)};
  assert.ok(!body.includes(publicPrefix),'Recovery publication attestation already exists');
  return body.trimEnd()+'\n\n'+publicPrefix+Buffer.from(JSON.stringify(proof)).toString('base64url')+' -->\n';
}
export async function inspectRecoveryPublication(part,release,producerRun,assets,manifest,read,readEvidence){
  assert.equal(part.repository,REPO);assert.equal(part.source_sha,PRODUCT);assert.equal(part.version,'2.0.0-dev.19');
  assert.deepEqual(part.producer,{run_id:Number(BUILD_RUN),run_attempt:1});
  const matches=[...(release.body||'').matchAll(/<!-- rsrs-cli3930-recovery:([A-Za-z0-9_-]+) -->/g)];
  assert.equal(matches.length,1,'Missing or duplicate durable recovery attestation');
  assert.equal((release.body||'').split(publicPrefix).length,2);
  const bytes=Buffer.from(matches[0][1],'base64url');assert.equal(bytes.toString('base64url'),matches[0][1]);
  const proof=JSON.parse(bytes),source=proof.source,publisher=proof.publisher;
  const fence=readFence(release.body);
  assert.equal(String(fence?.run_id),String(publisher.run_id));assert.equal(fence.source_sha,PRODUCT);
  assert.equal(fence.version,part.version);assert.equal(fence.phase,'fenced');
  assert.equal(proof.schema,1);assert.deepEqual(source.producer,requestedProducer());
  assert.equal(source.sha,PRODUCT);assert.equal(source.version,part.version);assert.equal(source.repository,REPO);
  assert.equal(source.workflow,recoveryWorkflow);assert.match(proof.manifest_sha256,/^[a-f0-9]{64}$/);assert.match(proof.acceptance_sha256,/^[a-f0-9]{64}$/);
  const foundProof=assets.filter(a=>a.name===recoveryProofName);assert.equal(foundProof.length,1,'Missing durable recovery preimage');
  assert.ok(positive(foundProof[0].id));assert.equal(foundProof[0].state,'uploaded');
  assert.equal(proof.evidence?.name,recoveryProofName);assert.ok(positive(proof.evidence.size));
  assert.equal(foundProof[0].size,proof.evidence.size);assert.equal(foundProof[0].digest,'sha256:'+proof.evidence.sha256);
  const evidenceBytes=await readEvidence(foundProof[0]);
  assert.equal(evidenceBytes.length,proof.evidence.size);assert.equal(hash(evidenceBytes),proof.evidence.sha256);
  const evidence=JSON.parse(evidenceBytes);
  assert.equal(hash(JSON.stringify(evidence.candidate)),proof.manifest_sha256,'Candidate preimage hash differs');
  assert.equal(hash(JSON.stringify(evidence.acceptance)),proof.acceptance_sha256,'Acceptance preimage hash differs');
  const result=evidence.acceptance,candidate=evidence.candidate;
  validatePreparationFull(result,source,manifest);
  assert.deepEqual(publicRecoveryResult(result),result);
  assert.deepEqual(result.continuation.producer,source.producer);assert.deepEqual(result.continuation.consumer,{run_id:source.run_id,run_attempt:source.run_attempt,sha:source.workflow_head_sha});
  assert.deepEqual(candidate.source,{repository:REPO,sha:PRODUCT,version:part.version,run_id:Number(BUILD_RUN),run_attempt:1});
  assert.equal(candidate.kind,'unpublished-cli-candidate');assert.equal(candidate.schema,1);
  assert.deepEqual(result.continuation.scripts,proof.scripts);assert.equal(result.manifest_sha256,proof.manifest_sha256);
  assert.equal(result.full_passed,true);assert.equal(result.gui_passed,true);assert.equal(result.scope,'database-in-place-upgrade');
  assert.equal(result.product_sources.cli,PRODUCT);assert.equal(result.product_sources.runtime,candidate.runtime.source_sha);
  assert.ok(result.actual_processes.length>0&&result.actual_processes.every(p=>p.manifest_sha256===proof.manifest_sha256&&manifest.targets.some(({triple:t})=>
    candidate.runtime.assets.some(a=>a.name===`rsrs-runtime-${t}${t.includes('windows')?'.exe':''}`&&a.sha256===p.image_sha256)&&
    candidate.runtime.assets.some(a=>a.name===`rsrs-runtime-${t}.tar.gz`&&a.sha256===p.bundle_sha256))),'Acceptance Runtime hashes differ from the original candidate');
  assert.equal(proof.scripts.producer_sha,PRODUCT);assert.equal(proof.scripts.consumer_sha,source.workflow_head_sha);
  for(const key of ['native_steps_sha256','cloud_steps_sha256','unchanged_tree_sha256'])assert.match(proof.scripts[key],/^[a-f0-9]{64}$/);
  const consumer=await read(`actions/runs/${source.run_id}/attempts/${source.run_attempt}`);
  validateRecoveryRuns(producerRun,consumer,source.producer,source);
  assert.equal(consumer.status,'completed');assert.equal(consumer.conclusion,'success');
  const jobs=async s=>{
    const result=[];
    for(let page=1;;page++){
      const response=await read(`actions/runs/${s.run_id}/attempts/${s.run_attempt}/jobs?per_page=100&page=${page}`);
      assert.ok(Array.isArray(response.jobs)&&response.jobs.length<=100);result.push(...response.jobs);
      if(response.jobs.length<100)return result;
    }
  };
  const original=await jobs(source.producer),current=await jobs(source);
  recoveryJobs(original,current,source.producer,source,manifest);
  const receiptJobs=current.filter(j=>j.name==='preparation-receipt');assert.equal(receiptJobs.length,1);
  assert.equal(receiptJobs[0].status,'completed');assert.equal(receiptJobs[0].conclusion,'success');
  assert.equal(publisher.repository,REPO);assert.equal(publisher.workflow,'.github/workflows/release.yml');
  assert.equal(publisher.sha,PRODUCT);assert.equal(publisher.version,part.version);assert.equal(publisher.release_id,part.release_id);
  assert.ok(positive(publisher.run_id)&&positive(publisher.run_attempt));assert.notEqual(String(publisher.run_id),String(source.run_id));assert.notEqual(String(publisher.run_id),BUILD_RUN);
  assert.match(publisher.workflow_head_sha,/^[a-f0-9]{40}$/);
  const publication=await read(`actions/runs/${publisher.run_id}/attempts/${publisher.run_attempt}`);
  assert.equal(publication.id,Number(publisher.run_id));assert.equal(publication.run_attempt,Number(publisher.run_attempt));
  assert.equal(publication.head_sha,publisher.workflow_head_sha);assert.equal(publication.head_branch,'main');assert.equal(publication.event,'workflow_dispatch');
  assert.equal(publication.head_repository?.full_name,REPO);assert.equal(publication.path,publisher.workflow);
  assert.equal(publication.status,'completed');assert.equal(publication.conclusion,'success');
  const publishedJobs=await jobs(publisher);
  for(const name of ['prepared-import','publication-ready','publish']){
    const found=publishedJobs.filter(j=>j.name===name);assert.equal(found.length,1);
    assert.equal(found[0].status,'completed');assert.equal(found[0].conclusion,'success');
  }
  const start=Date.parse(publication.created_at),published=Date.parse(release.published_at),end=Date.parse(publishedJobs.find(j=>j.name==='publish').completed_at);
  const prepared=Date.parse(receiptJobs[0].completed_at);
  assert.ok([start,published,end,prepared].every(Number.isFinite)&&prepared<=start&&start<=published&&published<=end,'Recovery/publication clocks do not bind the Release');
  assert.deepEqual(proof.assets.map(a=>a.file).sort(),manifest.targets.flatMap(t=>[`cli-build-${t.triple}.json`,`rsrs-${t.triple}${t.triple.includes('windows')?'.exe':''}`]).sort());
  for(const a of proof.assets){
    const found=assets.filter(b=>b.name===a.file);assert.equal(found.length,1);
    assert.ok(positive(a.size));assert.match(a.sha256,/^[a-f0-9]{64}$/);
    assert.equal(found[0].size,a.size);assert.equal(found[0].digest,'sha256:'+a.sha256);
  }
  return {consumer:{run_id:source.run_id,run_attempt:source.run_attempt,sha:source.workflow_head_sha},publisher,
    manifest_sha256:proof.manifest_sha256,acceptance_sha256:proof.acceptance_sha256,runtime:candidate.runtime};
}
export function planContinuation(root){
  const producer=requestedProducer(),source=currentSource(producer),context=recoveryContext(source,{planning:true});
  const candidate=readCandidate(context,root);
  output({sha:producer.sha,version:producer.version,producer_run:producer.run_id,producer_attempt:producer.run_attempt,
    candidate:JSON.stringify(candidate),client2_release:candidate.client2.release,client2_commit:candidate.client2.source_sha,
    native:JSON.stringify(context.original.filter(j=>j.name.startsWith('native-regression')&&j.conclusion==='failure').map(j=>({target:targetOf(j),os:osFor(targetOf(j))}))),
    cloud:JSON.stringify(context.original.filter(j=>j.name.startsWith('cloud-sweep (')&&j.conclusion==='failure').map(j=>({target:targetOf(j),os:osFor(targetOf(j))}))),
    suffix:suffix(source)});
  return context;
}
export function nativeContinuation(destination){
  const producer=requestedProducer(),context=recoveryContext(currentSource(producer),{planning:true});
  const t=process.env.CLI_TARGET;assert.ok(context.original.some(j=>retryable(j)&&targetOf(j)===t&&j.conclusion==='failure'));
  downloadRecoveryArtifact(select(context,'cli-release-'+t,`validate / Release (${t})`),destination);
}
export function attestContinuation(root,outputFile){
  const producer=requestedProducer(),source=currentSource(producer),context=recoveryContext(source);
  const candidate=readCandidate(context,join(root,'candidate-selection')),anchors=recoveryArtifacts(context);
  for(const a of anchors)downloadRecoveryArtifact(a,join(root,a.logical_name));
  const assetsFolder=join(root,'release-assets');mkdirSync(assetsFolder);
  for(const t of context.manifest.targets){
    const target=t.triple;
    for(const file of [`rsrs-${target}${target.includes('windows')?'.exe':''}`,`cli-build-${target}.json`])copyFileSync(join(root,'cli-release-'+target,file),join(assetsFolder,file));
  }
  // Native fixtures and all bytes are verified by the unchanged full requirements.
  const assets=preparedAssets(assetsFolder,source,context.manifest);
  const full_result=completeCandidate(candidate,assets,root,context.jobs,source,{evidenceOwners:context.evidenceOwners});
  full_result.continuation={producer,consumer:{run_id:source.run_id,run_attempt:source.run_attempt,sha:source.workflow_head_sha},
    scripts:context.scripts,artifacts:anchors,failed_artifacts:failedArtifacts(context),failed_jobs:context.original.filter(j=>retryable(j)&&j.conclusion==='failure').map(j=>({id:j.id,name:j.name,run_attempt:j.run_attempt}))};
  const receipt=createPreparation({...context,assets,packs:preparedPacks(join(root,'npm-release-packages'),source,context.manifest),full_result});
  writeFileSync(outputFile,JSON.stringify(receipt,null,2)+'\n');return receipt;
}
if(process.argv[1]&&pathToFileURL(resolve(process.argv[1])).href===import.meta.url){
  const [action,folder,file]=process.argv.slice(2);
  if(action==='plan')planContinuation(folder);
  else if(action==='native')nativeContinuation(folder);
  else if(action==='attest')attestContinuation(folder,file);
  else throw Error('Expected plan, native or attest');
}
