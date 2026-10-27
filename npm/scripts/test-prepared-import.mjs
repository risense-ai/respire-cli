import test from 'node:test';
import assert from 'node:assert/strict';
import {createPreparation,preparationLink} from './release-preparation.mjs';
import {validateImportedEvidence,importedAnchor,validateImportAnchor,assertImportPin,assertImportSelection,assertImportedContents} from './prepared-import.mjs';

const sha='a'.repeat(40),workflowSha='c'.repeat(40),hash='b'.repeat(64),version='1.2.3-dev.4';
const time=n=>`2026-10-27T00:${String(n).padStart(2,'0')}:00Z`;
const triples=['x86_64-unknown-linux-gnu','x86_64-unknown-linux-musl','aarch64-apple-darwin','x86_64-pc-windows-msvc'];
const manifest={cliVersion:version,npmScope:'@rsrsai/cli',targets:triples.map((triple,i)=>({triple,pkg:`@rsrsai/platform-${i}`}))};
const source={repository:'risense-ai/respire-cli',workflow:'.github/workflows/release.yml',run_id:'701',run_attempt:1,sha,version,channel:'dev',release_id:42};
function fixture(){
  const original={repository:source.repository,workflow:source.workflow,run_id:'700',run_attempt:1,sha,version};
  const job=name=>({name,status:'completed',conclusion:'success',started_at:time(0),completed_at:time(3)});
  const jobs=[...triples.map(t=>job(`validate / Release (${t})`)),job('validate / npm-dry-run'),
    ...triples.map(t=>job(`native-regression / Native (${t})`)),...triples.slice(1).map(t=>job(`cloud-sweep (runner, ${t})`)),
    ...triples.slice(2).flatMap(t=>[job(`Native migration (${t})`),job(`Migration gate (${t})`)]),job('api-smoke')];
  const run={id:700,run_attempt:1,path:source.workflow,event:'workflow_dispatch',head_branch:'main',head_sha:sha,
    head_repository:{full_name:source.repository},status:'in_progress',updated_at:time(5)};
  const ci={id:600,run_attempt:1,path:'.github/workflows/ci.yml',event:'push',head_branch:'main',head_sha:sha,
    head_repository:{full_name:source.repository},status:'completed',conclusion:'success',run_started_at:time(0),updated_at:time(2)};
  const artifacts=[...triples.map(t=>`cli-release-${t}`),'npm-release-validation','npm-release-packages'].map((name,i)=>({
    id:i+1,name,size_in_bytes:100,digest:`sha256:${hash}`,expired:false,workflow_run:{id:700,head_sha:sha}}));
  const assets=triples.flatMap(t=>[`rsrs-${t}${t.includes('windows')?'.exe':''}`,`rsrs-${t}-runtime.tar.gz`,`cli-build-${t}.json`]).map(file=>({file,size:100,sha256:hash}));
  const packs=[...manifest.targets.map(t=>t.pkg),manifest.npmScope].map((name,i)=>({name,version,file:`pack-${i}.tgz`,size:100,sha256:hash}));
  const identity={hashes:{'Cargo.lock':hash,'rust-toolchain.toml':hash},sdk:[]};
  const history={source:original,identity,manifest,run,jobs,ci,artifacts,assets,packs};
  const proof=createPreparation({...history,now:time(4)});
  history.run={...run,status:'completed',conclusion:'success'};
  const origin=preparationLink(proof,{id:90,name:'release-prepared-700-1',size_in_bytes:100,digest:`sha256:${hash}`,expired:false,workflow_run:{id:700,head_sha:sha}});
  const owner={repository:source.repository,workflow:source.workflow,run_id:'701',run_attempt:1,sha,version,workflow_head_sha:workflowSha,import_job_id:'1000'};
  const receipt={schema:1,kind:'prepared-import',state:'verified-copy',owner,origin,preparation:proof,
    validated_assets:structuredClone(assets),validated_packs:structuredClone(packs),imported_at:time(7)};
  const ownerRun={id:701,run_attempt:1,path:source.workflow,event:'workflow_dispatch',head_branch:'main',head_sha:workflowSha,
    head_repository:{full_name:source.repository},status:'in_progress',created_at:time(6)};
  const ownerJobs=[{id:1000,name:'prepared-import',status:'completed',conclusion:'success',started_at:time(6),completed_at:time(8)}];
  const metadata={id:99,name:'prepared-import-701-1',size_in_bytes:100,digest:`sha256:${hash}`,expired:false,workflow_run:{id:701,head_sha:workflowSha}};
  return {receipt,source:structuredClone(source),manifest,context:{ownerRun,ownerJobs,history},metadata};
}

test('completed trusted import keeps exact selected CLI SHA even when workflow main has advanced',()=>{
  const f=fixture();assert.equal(validateImportedEvidence(f.receipt,f.source,f.manifest,f.context),f.receipt);
  assert.notEqual(f.context.ownerRun.head_sha,f.source.sha);
  const anchor=importedAnchor(f.receipt,f.metadata,f.context.ownerRun);assert.equal(validateImportAnchor(anchor,f.source),anchor);
});
test('wrong source/version, owner attempt/repository, import job or immutable origin cannot authorize reuse',()=>{
  const mutations=[f=>f.source.sha='f'.repeat(40),f=>f.source.version='1.2.3-dev.5',f=>f.receipt.owner.run_attempt=2,
    f=>f.context.ownerRun.head_repository.full_name='fork/respire-cli',f=>f.context.ownerRun.head_sha=sha,
    f=>f.receipt.owner.import_job_id='1001',f=>f.receipt.origin.source.run_id='702',
    f=>f.receipt.origin.receipt_sha256='f'.repeat(64),f=>f.receipt.preparation.identity.sdk.push({target:'foreign'}),
    f=>f.receipt.validated_assets[0].sha256='f'.repeat(64),f=>f.receipt.validated_packs.pop()];
  for(const mutate of mutations){const f=structuredClone(fixture());mutate(f);assert.throws(()=>validateImportedEvidence(f.receipt,f.source,f.manifest,f.context));}
});
test('missing/duplicate/failed/cancelled/skipped import and failed original gates remain blocking',()=>{
  for(const mode of ['missing','duplicate','failure','cancelled','skipped','in_progress']){
    const f=fixture();
    if(mode==='missing')f.context.ownerJobs=[];
    else if(mode==='duplicate')f.context.ownerJobs.push({...f.context.ownerJobs[0]});
    else if(mode==='in_progress')f.context.ownerJobs[0].status=mode;
    else f.context.ownerJobs[0].conclusion=mode;
    assert.throws(()=>validateImportedEvidence(f.receipt,f.source,f.manifest,f.context),mode);
  }
  const f=fixture();f.context.history.jobs[0].conclusion='skipped';assert.throws(()=>validateImportedEvidence(f.receipt,f.source,f.manifest,f.context));
});
test('preparation must finish before actual publication trigger and import must fit real job clocks',()=>{
  for(const mutate of [f=>f.context.ownerRun.created_at=time(4),f=>f.receipt.imported_at=time(9),
    f=>f.context.ownerJobs[0].started_at='invalid',f=>f.context.ownerJobs[0].completed_at=time(5)]){
    const f=fixture();mutate(f);assert.throws(()=>validateImportedEvidence(f.receipt,f.source,f.manifest,f.context));
  }
});
test('only verified current copies may outlive original archive availability; expired current proof is refused',()=>{
  const f=fixture();f.context.history.artifacts=[];
  assert.equal(validateImportedEvidence(f.receipt,f.source,f.manifest,f.context),f.receipt);
  f.metadata.expired=true;assert.throws(()=>importedAnchor(f.receipt,f.metadata,f.context.ownerRun));
});
test('readiness pins both current import and original preparation',()=>{
  const f=fixture(),anchor=importedAnchor(f.receipt,f.metadata,f.context.ownerRun),result={receipt:f.receipt,anchor};
  const pin={artifact_id:99,artifact_digest:anchor.artifact.digest,receipt_sha256:anchor.receipt_sha256};
  assert.equal(assertImportPin(result,pin),result);
  assert.throws(()=>assertImportPin(result,{...pin,artifact_id:100}));
  assert.throws(()=>assertImportPin(result,{...pin,receipt_sha256:'f'.repeat(64)}));
  const old={attempt:1,artifact_id:90,artifact_digest:f.receipt.origin.artifact.digest,receipt_sha256:f.receipt.origin.receipt_sha256};
  assert.equal(assertImportSelection(result,700,old),result);
  assert.throws(()=>assertImportSelection(result,702,old));
  assert.throws(()=>assertImportSelection(result,700,{...old,attempt:2}));
});
test('optional historical byte parameters cannot substitute for mandatory write-boundary folders',()=>{
  for(const folders of [[undefined,undefined],['assets',undefined],[undefined,'packs'],['','packs']]){
    assert.throws(()=>assertImportedContents(source,manifest,...folders,{}),/Mandatory local asset and tarball folders missing/);
  }
});
