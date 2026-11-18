// A new consumer of frozen bytes; original jobs, metadata and failed reports stay immutable.
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {mkdirSync,readFileSync,writeFileSync,rmSync,copyFileSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {api,pages,output} from './release-publication.mjs';
import {validateCandidate,completeCandidate} from './candidate-artifact.mjs';
import {preparationInputs,preparedAssets,preparedPacks,createPreparation} from './release-preparation.mjs';

export const continuationWorkflow='.github/workflows/release-continuation.yml';
export const windowsTarget='x86_64-pc-windows-msvc';
const REPO='risense-ai/respire-cli',positive=n=>Number.isSafeInteger(Number(n))&&/^[1-9]\d*$/.test(String(n));
const hash=b=>createHash('sha256').update(b).digest('hex');
const nativeName=`native-regression / Native (${windowsTarget})`;
const readJobs=s=>pages(`repos/${REPO}/actions/runs/${s.run_id}/attempts/${s.run_attempt}/jobs?per_page=100`).flatMap(p=>p.jobs);
const readArtifacts=s=>pages(`repos/${REPO}/actions/runs/${s.run_id}/artifacts?per_page=100`).flatMap(p=>p.artifacts);
const originOwner=s=>({sha:s.sha,run_id:Number(s.run_id),run_attempt:Number(s.run_attempt)});

export function validateContinuationRuns(producerRun,consumerRun,producer,consumer){
  for(const [run,s,path] of [[producerRun,producer,'.github/workflows/release.yml'],[consumerRun,consumer,continuationWorkflow]]){
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
export function continuationScripts(producerSHA,consumerSHA,{cwd=process.cwd()}={}){
  const allowed=new Set([continuationWorkflow,'.github/workflows/release-native-validation.yml','.github/workflows/release.yml',
    'npm/scripts/release-continuation.mjs','npm/scripts/release-preparation.mjs','npm/scripts/candidate-artifact.mjs',
    'npm/scripts/extract-artifact.mjs','npm/scripts/test-release-preparation.mjs','npm/scripts/test-prepared-import.mjs',
    'npm/scripts/test-release-regression-contract.mjs']);
  execFileSync('git',['merge-base','--is-ancestor',producerSHA,consumerSHA],{cwd});
  const changed=execFileSync('git',['diff','--name-only',producerSHA,consumerSHA],{cwd,encoding:'utf8'}).trim().split(/\r?\n/).filter(Boolean);
  assert.ok(changed.every(file=>allowed.has(file)),'Product, fixture or unrelated CI source changed since producer');
  const nativeTail=sha=>{
    const text=execFileSync('git',['show',`${sha}:.github/workflows/release-native-validation.yml`],{cwd,encoding:'utf8'}).replace(/\r\n/g,'\n');
    const start=text.indexOf('      - name: Verify and extract the release binary\n');assert.ok(start>=0,'Missing original native entry');
    return text.slice(start);
  };
  const originalSteps=nativeTail(producerSHA);assert.equal(nativeTail(consumerSHA),originalSteps,'Windows native scope or commands changed');
  const tree=execFileSync('git',['ls-tree','-r',producerSHA],{cwd,encoding:'utf8',maxBuffer:16*1024*1024});
  return {producer_sha:producerSHA,consumer_sha:consumerSHA,native_steps_sha256:hash(originalSteps),
    unchanged_tree_sha256:hash(tree.split('\n').filter(line=>!allowed.has(line.split('\t')[1])).join('\n'))};
}

export function continuationJobs(original,current,producer,consumer,manifest,{planning=false}={}){
  const originals=original.filter(j=>j.name===nativeName);
  assert.equal(originals.length,1);assert.equal(originals[0].status,'completed');assert.equal(originals[0].conclusion,'failure');
  assert.ok(positive(originals[0].id));
  assert.equal(originals[0].run_id,Number(producer.run_id));assert.equal(originals[0].run_attempt,Number(producer.run_attempt));
  assert.equal(originals[0].head_sha,producer.sha);
  const reused=original.filter(j=>j.name.startsWith('validate / Release (')||j.name==='validate / npm-dry-run'||j.name==='api-smoke'||
    j.name.startsWith('cloud-sweep (')||j.name.startsWith('native-regression / Native (')&&j.name!==nativeName);
  const replacements=current.filter(j=>j.name===nativeName);
  assert.equal(replacements.length,planning?0:1,'Require exactly the new complete Windows native job');
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
  for(const name of required){
    if(planning&&name===nativeName)continue;
    assert.equal(joined.filter(j=>j.name===name||j.name.startsWith('cloud-sweep (')&&j.name.endsWith(', '+name+')')).length,1,'Missing full evidence: '+name);
  }
  return {jobs:[...joined,...current.filter(j=>j.name==='preparation-receipt')],evidenceOwners:owners};
}

export function continuationArtifact(artifacts,name,job,owner,{failed=false}={}){
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
export function downloadContinuationArtifact(a,destination,{transport=execFileSync}={}){
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
  assert.equal(execFileSync('git',['rev-parse','HEAD'],{encoding:'utf8'}).trim(),process.env.GITHUB_SHA);
  return {repository:REPO,workflow:continuationWorkflow,run_id:process.env.GITHUB_RUN_ID,run_attempt:Number(process.env.GITHUB_RUN_ATTEMPT),
    sha:producer.sha,version:producer.version,workflow_head_sha:process.env.GITHUB_SHA,producer};
}
export function continuationContext(source,{planning=false}={}){
  const producer=source.producer;
  const producerRun=api(`repos/${REPO}/actions/runs/${producer.run_id}`),run=api(`repos/${REPO}/actions/runs/${source.run_id}`);
  validateContinuationRuns(producerRun,run,producer,source);
  const scripts=continuationScripts(producer.sha,source.workflow_head_sha);
  const inputs=preparationInputs(producer.sha,producer.version),original=readJobs(producer),current=readJobs(source);
  const joined=continuationJobs(original,planning?[]:current,producer,source,inputs.manifest,{planning});
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
  return continuationArtifact(replacement?context.consumerArtifacts:context.artifacts,name,jobs[0],s);
}
export function continuationArtifacts(context){
  const anchors=[],take=(...args)=>anchors.push(select(context,...args));
  for(const {triple:target} of context.manifest.targets){
    take('cli-release-'+target,`validate / Release (${target})`);
    for(const prefix of ['candidate-assets-','resident-concurrency-','published-upgrades-'])take(prefix+target,`native-regression / Native (${target})`,target===windowsTarget);
    if(target==='x86_64-unknown-linux-gnu'){take('gnu-login-interruption',`native-regression / Native (${target})`);continue;}
    const cloud=context.original.filter(j=>j.name.startsWith('cloud-sweep (')&&j.name.endsWith(', '+target+')'));assert.equal(cloud.length,1);
    take('base-release-sweep-'+target,cloud[0].name);
    if(target.includes('linux'))for(const prefix of ['release-sweep-','secret-service-profile-migration-'])take(prefix+target,cloud[0].name);
  }
  for(const name of ['npm-release-validation','npm-release-packages'])take(name,'validate / npm-dry-run');
  take('dev-api-coverage','api-smoke');take('client2-published-online-'+windowsTarget,nativeName,true);
  return anchors;
}
function failedArtifacts(context){
  const job=context.original.find(j=>j.name===nativeName),owner=originOwner(context.source.producer);
  return ['candidate-assets-','resident-concurrency-','published-upgrades-','client2-published-online-'].map(p=>p+windowsTarget)
    .filter(name=>context.artifacts.some(a=>a.name===name))
    .map(name=>({...continuationArtifact(context.artifacts,name,job,owner,{failed:true}),reused:false}));
}
export function validateContinuationEvidence(result,context){
  const c=result.continuation,s=context.source;
  assert.deepEqual(c?.producer,s.producer);
  assert.deepEqual(c.consumer,{run_id:s.run_id,run_attempt:s.run_attempt,sha:s.workflow_head_sha});
  assert.deepEqual(c.scripts,context.scripts);
  assert.deepEqual(c.artifacts,continuationArtifacts(context));
  assert.deepEqual(c.failed_artifacts,failedArtifacts(context));
  assert.equal(c.failed_native_job_id,context.original.find(j=>j.name===nativeName)?.id);
  assert.ok(result.reports.every(r=>c.artifacts.some(a=>a.name===r.artifact)),'Unbound full report');
}
function readCandidate(context,root){
  const target='aarch64-pc-windows-msvc',name='candidate-assets-'+target;
  downloadContinuationArtifact(select(context,name,`native-regression / Native (${target})`),join(root,name));
  const c=JSON.parse(readFileSync(join(root,name,'candidate-assets-receipt.json'))).candidate,p=context.source.producer;
  validateCandidate(c,{CLI_SHA:p.sha,CLI_VERSION:p.version,GITHUB_RUN_ID:p.run_id,GITHUB_RUN_ATTEMPT:p.run_attempt,GITHUB_SHA:p.sha});
  assert.equal(c.source.repository,p.repository);return c;
}
function requestedProducer(){
  assert.ok(positive(process.env.CONTINUATION_RUN)&&positive(process.env.CONTINUATION_ATTEMPT));
  const run=api(`repos/${REPO}/actions/runs/${process.env.CONTINUATION_RUN}`);
  return {repository:REPO,workflow:'.github/workflows/release.yml',run_id:process.env.CONTINUATION_RUN,
    run_attempt:Number(process.env.CONTINUATION_ATTEMPT),sha:run.head_sha,version:process.env.CLI_VERSION};
}
export function planContinuation(root){
  const producer=requestedProducer(),source=currentSource(producer),context=continuationContext(source,{planning:true});
  const candidate=readCandidate(context,root);
  output({sha:producer.sha,version:producer.version,producer_run:producer.run_id,producer_attempt:producer.run_attempt,
    candidate:JSON.stringify(candidate),client2_release:candidate.client2.release,client2_commit:candidate.client2.source_sha});
  return context;
}
export function nativeContinuation(destination){
  const producer=requestedProducer(),context=continuationContext(currentSource(producer),{planning:true});
  assert.equal(process.env.CLI_TARGET,windowsTarget);
  downloadContinuationArtifact(select(context,'cli-release-'+windowsTarget,`validate / Release (${windowsTarget})`),destination);
}
export function attestContinuation(root,outputFile){
  const producer=requestedProducer(),source=currentSource(producer),context=continuationContext(source);
  const candidate=readCandidate(context,join(root,'candidate-selection')),anchors=continuationArtifacts(context);
  for(const a of anchors)downloadContinuationArtifact(a,join(root,a.name));
  const assetsFolder=join(root,'release-assets');mkdirSync(assetsFolder);
  for(const t of context.manifest.targets){
    const target=t.triple;
    for(const file of [`rsrs-${target}${target.includes('windows')?'.exe':''}`,`cli-build-${target}.json`])copyFileSync(join(root,'cli-release-'+target,file),join(assetsFolder,file));
  }
  // Native fixtures and all bytes are verified by the unchanged full requirements.
  const assets=preparedAssets(assetsFolder,source,context.manifest);
  const full_result=completeCandidate(candidate,assets,root,context.jobs,source,{evidenceOwners:context.evidenceOwners});
  full_result.continuation={producer,consumer:{run_id:source.run_id,run_attempt:source.run_attempt,sha:source.workflow_head_sha},
    scripts:context.scripts,artifacts:anchors,failed_artifacts:failedArtifacts(context),failed_native_job_id:context.original.find(j=>j.name===nativeName).id};
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
