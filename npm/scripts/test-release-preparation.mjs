import test from 'node:test';
import {approvedRecoveryProducer} from './release-recovery-sources.mjs';
import {validateArmReplay, validateArmReplayInputs} from './release-recovery3930.mjs';
import assert from 'node:assert/strict';
import {mkdtempSync,writeFileSync,rmSync,readFileSync,mkdirSync,existsSync,readdirSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {createHash} from 'node:crypto';
import {spawnSync,execFileSync} from 'node:child_process';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {publishedFullFixture} from './full-report-fixture.mjs';
import {publishedAssetNames,inspectPublishedRelease,validateRecoveredRuntime} from './extract-artifact.mjs';
import {assertReleaseAssets} from './release-publication.mjs';
import {createPreparation,validatePreparation,preparedAssets,preparedPacks,validatePreparationRun} from './release-preparation.mjs';
import {completeCandidate} from './candidate-artifact.mjs';
import {fenceBody} from './publication-fence.mjs';
import {bindMuslReportOrigins,muslOldHashes,validateMuslReportProof,inspectMuslComposition,muslPreparationWorkflow,muslDiagnostic} from './release-recovery3930.mjs';
import {recoveryWorkflow,windowsTarget,validateRecoveryRuns,recoveryJobs,recoveryArtifact,recoveryArtifacts,
  downloadRecoveryArtifact,validateRecoveryEvidence,recoveryScripts,cloudScope,recoveryPublicationBody,recoveryPublicationEvidence,recoveryProofName} from './release-recovery3930.mjs';

const sha='3930ba500b96a0c52eb7aa735b7ddb4117ad4e9f',hash='b'.repeat(64),version='2.0.0-dev.19';
const targets=[['x86_64-unknown-linux-gnu','linux-x64-gnu'],['x86_64-unknown-linux-musl','linux-x64'],['aarch64-apple-darwin','macos-arm64'],['x86_64-pc-windows-msvc','win-x64']];
const manifest={cliVersion:version,npmScope:'@rsrsai/cli',targets:targets.map(([triple,name])=>({triple,pkg:`@rsrsai/${name}`}))};
const source={repository:'risense-ai/respire-cli',workflow:'.github/workflows/release.yml',run_id:'44276673815',run_attempt:1,sha,version};
const identity={hashes:{'Cargo.lock':hash,'rust-toolchain.toml':hash},sdk:targets.map(([target])=>({target,version:'1.0.2-dev.12',manifest_sha256:hash,archive_sha256:hash}))};
const time=minute=>`2026-10-27T00:${String(minute).padStart(2,'0')}:00Z`;
const job=name=>({name,status:'completed',conclusion:'success',started_at:time(0),completed_at:time(3)});
function fixture(){
  const jobs=[...targets.map(([t])=>job(`validate / Release (${t})`)),job('validate / npm-dry-run'),
    ...targets.map(([t])=>job(`native-regression / Native (${t})`)),
    ...targets.slice(1).map(([t])=>job(`cloud-sweep (runner, ${t})`)),
    job('api-smoke')];
  const run={id:44276673815,run_attempt:1,path:source.workflow,head_repository:{full_name:source.repository},head_sha:sha,
    head_branch:'main',event:'workflow_dispatch',status:'in_progress',updated_at:time(5)};
  const ci={id:600,run_attempt:1,path:'.github/workflows/ci.yml',head_repository:{full_name:source.repository},head_sha:sha,
    head_branch:'main',event:'push',status:'completed',conclusion:'success',run_started_at:time(0),updated_at:time(2)};
  const artifacts=[...targets.map(([t])=>`cli-release-${t}`),'npm-release-validation','npm-release-packages'].map((name,i)=>({
    name,id:i+1,size_in_bytes:100,digest:`sha256:${hash}`,expired:false,workflow_run:{id:44276673815,head_sha:sha}}));
  const assets=targets.flatMap(([t])=>[`rsrs-${t}${t.includes('windows')?'.exe':''}`,`rsrs-${t}-runtime.tar.gz`,`cli-build-${t}.json`]).map(file=>({file,size:100,sha256:hash}));
  const packs=[...targets.map(([,n])=>`@rsrsai/${n}`),'@rsrsai/cli'].map((name,i)=>({name,version,file:`pack-${i}.tgz`,size:100,sha256:hash}));
  jobs.push({id:900,name:'preparation-receipt',status:'in_progress',started_at:time(3)});
  const full_result={schema:2,scope:'database-in-place-upgrade',profile_import:{required:false,status:'not-run',diagnostic_workflow:'.github/workflows/migration-keyring-check.yml'},kind:'candidate-full',full_passed:true,gui_passed:true,harness_sha:source.sha,product_sources:{cli:source.sha},manifest_sha256:hash,run_id:Number(source.run_id),run_attempt:Number(source.run_attempt),historical_upgrades:manifest.targets.map(t=>({target:t.triple,profile:'full',all_published_sources_covered:true})),reports:[{artifact:'client2-published-online-x86_64-pc-windows-msvc',path:'report.json',sha256:hash}]};
  const context={source,identity,manifest,run,jobs,ci,artifacts,assets,packs,full_result,now:time(4)};
  const receipt=createPreparation(context);
  Object.assign(jobs.at(-1),{status:'completed',conclusion:'success',completed_at:time(4)});
  context.run={...context.run,status:'completed',conclusion:'success'};
  return {receipt,context};
}

test('exact successful main preparation proves all builds, packaging, CI and regression lanes',()=>{
  const {receipt,context}=fixture();
  assert.equal(validatePreparation(receipt,context),receipt);
  assert.equal(receipt.validation.completed_at,new Date(time(3)).toISOString());
  assert.equal(receipt.state,'validated-unpublished');
  assert.equal(receipt.accepted_at,undefined);assert.equal(receipt.install,undefined);
});
test('different source, attempt, repository, workflow, PR, fork and incomplete run cannot authorize reuse',()=>{
  const mutations=[r=>r.head_sha='f'.repeat(40),r=>r.run_attempt=2,r=>r.id=701,r=>r.head_branch='feature',
    r=>r.event='pull_request',r=>r.head_repository.full_name='fork/respire-cli',r=>r.path='.github/workflows/ci.yml',
    r=>r.status='in_progress',r=>r.conclusion='failure'];
  for(const mutate of mutations){const {receipt,context}=fixture();mutate(context.run);assert.throws(()=>validatePreparation(receipt,context));}
  assert.throws(()=>validatePreparationRun({...fixture().context.run,status:'in_progress'},source));
});
test('every required build, package validation, regression and exact push CI remains fail closed',()=>{
  const {context:sample}=fixture();
  for(let i=0;i<sample.jobs.length;i++)for(const mode of ['failure','cancelled','skipped','missing','duplicate']){
    const {receipt,context}=fixture();
    if(mode==='missing')context.jobs.splice(i,1);
    else if(mode==='duplicate')context.jobs.push({...context.jobs[i]});
    else context.jobs[i].conclusion=mode;
    assert.throws(()=>validatePreparation(receipt,context),`${i} ${mode}`);
  }
  for(const [key,value] of [['head_sha','f'.repeat(40)],['event','workflow_dispatch'],['run_attempt',2],['conclusion','cancelled']]){
    const {receipt,context}=fixture();context.ci[key]=value;assert.throws(()=>validatePreparation(receipt,context));
  }
});
test('SDK/toolchain changes, missing clocks, expired or substituted artifacts and different bytes are refused',()=>{
  const mutations=[
    ({identity})=>identity.hashes['rust-toolchain.toml']='c'.repeat(64),
    ({identity})=>identity.sdk[0].version='1.0.2-dev.13',
    ({jobs})=>delete jobs[0].completed_at,
    ({jobs})=>jobs[0].completed_at='invalid',
    ({artifacts})=>artifacts[0].expired=true,
    ({artifacts})=>artifacts[0].id=999,
    ({artifacts})=>artifacts[0].workflow_run.id=701,
    ({artifacts})=>artifacts[0].workflow_run.head_sha='f'.repeat(40),
    ({artifacts})=>artifacts[0].digest='sha256:'+'f'.repeat(64),
    ({assets})=>assets[0].sha256='f'.repeat(64),
    ({packs})=>packs[0].sha256='f'.repeat(64),
  ];
  for(const mutate of mutations){const {receipt,context}=structuredClone(fixture());mutate(context);assert.throws(()=>validatePreparation(receipt,context));}
});
test('receipt cannot change version/inventory or claim validation before work completes',()=>{
  for(const mutate of [r=>r.source.version='1.2.3-dev.5',r=>r.assets[0]=r.assets[1],r=>r.packs.pop(),
    r=>r.prepared_at='2026-02-30T00:00:00Z']){
    const {receipt,context}=structuredClone(fixture());mutate(receipt);assert.throws(()=>validatePreparation(receipt,context));
  }
});
test('preparation uses completed API gates and its successful producer despite runner clock skew',()=>{
  for(const now of ['2026-10-26T23:04:00Z','2026-10-27T01:04:00Z']){
    const {context}=structuredClone(fixture());
    context.run.status='in_progress';context.jobs.at(-1).status='in_progress';
    const receipt=createPreparation({...context,now});
    context.run.status='completed';context.jobs.at(-1).status='completed';
    assert.equal(validatePreparation(receipt,context),receipt);
  }
  for(const mutate of [c=>c.jobs.pop(),c=>c.jobs.push({...c.jobs.at(-1)}),
    c=>c.jobs.at(-1).id='invalid',c=>c.jobs.at(-1).started_at='invalid',
    c=>c.jobs.at(-1).completed_at=time(2),c=>c.jobs.at(-1).completed_at=time(6),
    c=>c.jobs.at(-1).conclusion='failure',c=>c.jobs.at(-1).status='in_progress']){
    const {receipt,context}=structuredClone(fixture());mutate(context);
    assert.throws(()=>validatePreparation(receipt,context));
  }
});

test('source CI may finish during producer setup before the attester reads its successful result',()=>{
  const {context}=structuredClone(fixture());
  context.jobs.at(-1).started_at=time(1);context.run.status='in_progress';context.jobs.at(-1).status='in_progress';
  const receipt=createPreparation(context);
  context.run.status='completed';context.jobs.at(-1).status='completed';
  assert.equal(validatePreparation(receipt,context),receipt);
});

test('actual synthetic asset files bind source, version, platform and binary/runtime hashes',()=>{
  for(const frontend of [false,true]){
  const folder=mkdtempSync(join(tmpdir(),'prepared-assets-'));
  const layout={...manifest,...(frontend?{artifactLayout:'cli-frontend-v2'}:{})};
  try{
    for(const t of manifest.targets){
      const binary=`rsrs-${t.triple}${t.triple.includes('windows')?'.exe':''}`,runtime=`rsrs-${t.triple}-runtime.tar.gz`;
      const content=Buffer.from(t.triple),sha256=createHash('sha256').update(content).digest('hex');
      writeFileSync(join(folder,binary),content);
      if(!frontend)writeFileSync(join(folder,runtime),content);
      writeFileSync(join(folder,`cli-build-${t.triple}.json`),JSON.stringify(frontend
        ? {schema_version:2,artifact_layout:layout.artifactLayout,git_sha:sha,version,target:t.triple,
          binary_file:binary,binary_size:content.length,binary_sha256:sha256,producer:{run_id:source.run_id,run_attempt:source.run_attempt}}
        : {schema_version:1,git_sha:sha,version,target:t.triple,
          binary_file:binary,runtime_file:runtime,binary_sha256:sha256,runtime_sha256:sha256}));
    }
    assert.equal(preparedAssets(folder,source,layout).length,frontend?8:12);
    if(frontend)assert.deepEqual(preparedAssets(folder,{...source,run_id:'701',producer:source},layout),preparedAssets(folder,source,layout));
    const metadata=join(folder,`cli-build-${targets[0][0]}.json`),original=JSON.parse(readFileSync(metadata));
    for(const mutate of frontend?[m=>m.binary_size++,m=>m.producer.run_attempt++,m=>m.producer.run_id='999',
      m=>m.runtime_file='unexpected-runtime.tar.gz',m=>m.schema_version=1]:[m=>m.schema_version=2]){
      const changed=structuredClone(original);mutate(changed);writeFileSync(metadata,JSON.stringify(changed));
      assert.throws(()=>preparedAssets(folder,source,layout));writeFileSync(metadata,JSON.stringify(original));
    }
    writeFileSync(join(folder,`rsrs-${targets[0][0]}`),'tampered');assert.throws(()=>preparedAssets(folder,source,layout));
  }finally{rmSync(folder,{recursive:true,force:true});}
  }
});
test('actual synthetic npm packs must match the full exact-version local pack index',()=>{
  const folder=mkdtempSync(join(tmpdir(),'prepared-packs-'));
  try{
    const packages=[...manifest.targets.map(t=>t.pkg),manifest.npmScope].map((name,i)=>{
      const file=`pack-${i}.tgz`,bytes=Buffer.from(name);writeFileSync(join(folder,file),bytes);
      return {name,version,file,sha256:createHash('sha256').update(bytes).digest('hex')};
    });
    writeFileSync(join(folder,'source-version.json'),JSON.stringify({schema_version:1,git_sha:sha,version,packages}));
    assert.equal(preparedPacks(folder,source,manifest).length,5);
    writeFileSync(join(folder,packages[0].file),'tampered');assert.throws(()=>preparedPacks(folder,source,manifest));
  }finally{rmSync(folder,{recursive:true,force:true});}

});

test('Release attests all full candidate consumers and publishes only verified imported bytes',async()=>{
  const release=readFileSync(new URL('../../.github/workflows/release.yml',import.meta.url),'utf8').replace(/\r\n/g,'\n');
  assert.match(release,/needs: \[plan, validate, native-regression, cloud-sweep, api-smoke\]/);
  assert.match(release,/release-preparation.mjs attest release-assets full-reports\/npm-release-packages release-prepared.json full-reports/);
  assert.match(release,/prepared_binary_run: \$\{\{ steps.prepared.outputs.prepared_binary_run \}\}/);
  assert.equal((release.match(/run-id: \$\{\{ needs.plan.outputs.prepared_binary_run \}\}/g)||[]).length,2);
  assert.equal((release.match(/git archive "\$GITHUB_SHA" npm\/scripts\/\{release-recovery3930,release-recovery-sources,release-preparation,candidate-artifact,extract-artifact,publication-acceptance,release-publication,verified-receipt\}.mjs \| tar -x/g)||[]).length,4);
  const continuation=readFileSync(new URL('../../.github/workflows/release-recovery3930.yml',import.meta.url),'utf8');
  assert.match(continuation,/uses: \.\/.github\/workflows\/release-native-validation.yml/);
  assert.match(continuation,/validation_profile: full/);
  assert.doesNotMatch(continuation,/contents: write|actions: write|GITHUB_(SHA|RUN_ID|RUN_ATTEMPT):|gh run rerun|gh workflow run/);
  const publisher=release.split('\n  publish:\n')[1];
  assert.match(publisher,/needs.prepared-import.result == 'success'/);
  assert.match(publisher,/needs.publication-ready.result == 'success'/);
  assert.match(publisher,/--reuse-packs npm\/release-packages --export-packs npm\/publication-packages/);
  assert.doesNotMatch(publisher,/--pack npm\/publication-packages/);
  const folder=mkdtempSync(join(tmpdir(),'musl-report-origins-'));
  try{
    const logical='published-upgrades-x86_64-unknown-linux-musl';
    const tags=['v1.0.7','v1.0.8','v1.0.9','v1.0.11','v1.0.11-dev.1','v1.0.12','v1.0.15','v1.0.16','v1.0.17-dev.6','v1.0.18','v1.0.19','v1.0.20'];
    const anchor=(id,name,run,conclusion)=>({id,name,digest:'sha256:'+'a'.repeat(64),owner:{run_id:run,run_attempt:1},conclusion});
    const origins={
      old:{directory:join(folder,'old'),anchor:anchor('14424335334',logical+'-recovery-44292748654-1',44292748654,'failure')},
      current:{directory:join(folder,'current'),anchor:anchor('2',logical+'-musl-source-3-1',3,'success')},
      summary:{directory:join(folder,'summary'),anchor:anchor('4','musl3930-composition-5-1',5,'success')}};
    origins.old.anchor.digest='sha256:23646cc75cf81d80852f752e7391994dd0751fe296a112707bfce55e458aef31';
    const reports=[];
    for(const path of ['published-upgrades.json',...tags.map(tag=>tag+'/results/real-account-return-verification.json')]){
      const origin=path==='published-upgrades.json'?origins.summary:path.startsWith('v1.0.8/')?origins.current:origins.old;
      const file=join(origin.directory,path);mkdirSync(join(file,'..'),{recursive:true});
      const bytes=JSON.stringify({test_only:path});writeFileSync(file,bytes);
      reports.push({artifact:logical,path,sha256:createHash('sha256').update(bytes).digest('hex')});
    }
    const result={reports,historical_upgrades:[{target:'x86_64-unknown-linux-musl',passed:tags,not_applicable:[]}]};
    const bound=bindMuslReportOrigins(result,origins);
    assert.equal(bound.reports.filter(r=>r.artifact===origins.old.anchor.name).length,11);
    assert.equal(bound.reports.filter(r=>r.artifact===origins.current.anchor.name).length,1);
    assert.equal(bound.reports.filter(r=>r.artifact===origins.summary.anchor.name).length,1);
    assert.ok(result.reports.every(r=>r.artifact===logical));
    const wrong=structuredClone(result);wrong.reports[1].sha256='0'.repeat(64);
    assert.throws(()=>bindMuslReportOrigins(wrong,origins),/absent from its claimed ZIP/);
    assert.throws(()=>bindMuslReportOrigins(result,{...origins,summary:origins.current}));
    const missing=structuredClone(result);missing.reports.pop();
    assert.throws(()=>bindMuslReportOrigins(missing,origins),/twelve sources/);
    writeFileSync(join(origins.current.directory,'v1.0.8/results/real-account-return-verification.json'),'changed');
    assert.throws(()=>bindMuslReportOrigins(result,origins),/absent from its claimed ZIP/);
  }finally{rmSync(folder,{recursive:true,force:true});}
  const fixed='710e6b13ff588c02157d8d677e59e8f21c16beae',first='d'.repeat(40),validator='e'.repeat(40);
  const composedSource={...source,workflow:muslPreparationWorkflow,run_id:'13',workflow_head_sha:'c'.repeat(40),producer:source,
    fixture_commit:fixed,diagnostic:{...muslDiagnostic}};
  const fixture={commit:fixed,files:{'scripts/test-published-upgrades.py':validator}};
  const logical='published-upgrades-x86_64-unknown-linux-musl';
  const sourceRows=[...Object.entries(muslOldHashes),['v1.0.8','a'.repeat(64)]].map(([tag,digest])=>({source:tag,contract:'historical-385',
    fixture_commit:tag==='v1.0.8'?fixed:first,validator_blob:validator,report_sha256:digest}));
  const old={name:logical+'-recovery-44292748654-1'},current={name:logical+`-musl-source-${muslDiagnostic.run_id}-1`},summary={name:'musl3930-composition-13-1'};
  const proof={manifest_sha256:hash,historical_upgrades:[{target:'x86_64-unknown-linux-musl',passed:sourceRows.map(r=>r.source),not_applicable:[]}],
    reports:[...sourceRows.map(r=>({artifact:r.source==='v1.0.8'?current.name:old.name,path:r.source+'/results/real-account-return-verification.json',sha256:r.report_sha256})),
      {artifact:summary.name,path:'published-upgrades.json',sha256:hash}],continuation:{artifacts:[old,current,summary],musl:{schema:1,kind:'fixed-musl3930-composition',
        producer:source,diagnostic:composedSource.diagnostic,harness_sha:composedSource.workflow_head_sha,fixture,runtime_sha256:hash,candidate_sha256:hash,
        sources:sourceRows,summary_sha256:hash,summary_artifact:summary,source_artifacts:{old,current}}}};
  validateMuslReportProof(proof,composedSource,fixture,first);
  for(const mutate of [p=>p.reports[0].artifact=current.name,p=>p.continuation.musl.sources[0].report_sha256='0'.repeat(64),
    p=>p.continuation.musl.sources.pop(),p=>p.reports.at(-1).artifact=current.name,p=>p.continuation.musl.diagnostic.run_attempt=2]){
    const bad=structuredClone(proof);mutate(bad);assert.throws(()=>validateMuslReportProof(bad,composedSource,fixture,first));
  }
  for(const file of ['dev-legacy-vault-smoke.py','dev-migration-keyring.py','test-published-upgrades.py','test-real-m3-account-switch.py',
    'test-dev-credential-alias-fixtures.py','test-full-release-diagnostics.py','test_published_upgrade_policy.py'])fixture.files['scripts/'+file]=validator;
  const required=[...manifest.targets.map(t=>`validate / Release (${t.triple})`),'validate / npm-dry-run','api-smoke',
    ...manifest.targets.map(t=>`native-regression / Native (${t.triple})`),...manifest.targets.filter(t=>t.triple!=='x86_64-unknown-linux-gnu').map(t=>`cloud-sweep (runner, ${t.triple})`)];
  const originalJobs=required.map((name,i)=>({name,id:100+i,status:'completed',conclusion:name==='native-regression / Native (x86_64-unknown-linux-musl)'?'failure':'success',
    run_id:Number(source.run_id),run_attempt:1,head_sha:source.sha}));
  const oldNative={name:'native-regression / Native (x86_64-unknown-linux-musl)',id:400,status:'completed',conclusion:'failure',run_id:44292748654,run_attempt:1,head_sha:first,
    steps:['Verify OS autostart registration from verified release bytes','Install and probe BGE CPU inference'].map(name=>({name,conclusion:'success'}))};
  const newNative={...oldNative,id:134805531846,conclusion:'success',run_id:Number(muslDiagnostic.run_id),head_sha:composedSource.diagnostic.sha};
  const compose={name:'compose',id:402,status:'completed',conclusion:'success',run_id:13,run_attempt:1,head_sha:composedSource.workflow_head_sha};
  for(const [a,j,id] of [[old,oldNative,'14424335334'],[current,newNative,'600'],[summary,compose,'601']])Object.assign(a,
    {id,job_id:j.id,size:1,digest:'sha256:'+'a'.repeat(64),conclusion:j.conclusion,owner:{run_id:j.run_id,run_attempt:1,sha:j.head_sha}});
  old.digest='sha256:23646cc75cf81d80852f752e7391994dd0751fe296a112707bfce55e458aef31';
  const firstRun={status:'completed',conclusion:'failure',path:recoveryWorkflow,head_branch:'main',event:'workflow_dispatch',head_repository:{full_name:source.repository},head_sha:first};
  const diagnosticRun={...firstRun,id:Number(muslDiagnostic.run_id),run_attempt:1,conclusion:'success',path:'.github/workflows/release-musl3930.yml',head_sha:composedSource.diagnostic.sha};
  const read=async path=>path==='actions/runs/44292748654/attempts/1'?firstRun:path===`actions/runs/${muslDiagnostic.run_id}/attempts/1`?diagnosticRun:
    path==='commits/385c3c9'?{sha:first}:path.startsWith('contents/')?{type:'file',sha:validator}:assert.fail('Unexpected read '+path);
  const readJobs=async owner=>String(owner.run_id)==='44292748654'?[oldNative]:String(owner.run_id)===muslDiagnostic.run_id?[newNative]:assert.fail('Unexpected job owner');
  await inspectMuslComposition(composedSource,proof,originalJobs,[compose],manifest,read,readJobs);
  diagnosticRun.status='in_progress';await assert.rejects(inspectMuslComposition(composedSource,proof,originalJobs,[compose],manifest,read,readJobs));diagnosticRun.status='completed';
  compose.conclusion='cancelled';await assert.rejects(inspectMuslComposition(composedSource,proof,originalJobs,[compose],manifest,read,readJobs));compose.conclusion='success';
  current.owner.run_attempt=2;await assert.rejects(inspectMuslComposition(composedSource,proof,originalJobs,[compose],manifest,read,readJobs));current.owner.run_attempt=1;
  const mixed=spawnSync(process.platform==='win32'?'py':'python3',[...(process.platform==='win32'?['-3']:[]),'-c',String.raw`
import copy,json,pathlib,runpy,tempfile
m=runpy.run_path('scripts/merge-musl3930-upgrades.py')['merge']
tags=['v1.0.7','v1.0.8','v1.0.9','v1.0.11','v1.0.11-dev.1','v1.0.12','v1.0.15','v1.0.16','v1.0.17-dev.6','v1.0.18','v1.0.19','v1.0.20']
policy=runpy.run_path('scripts/published_upgrade_policy.py')['DATABASE_DEV_CHECKPOINTS']
base={k:True for k in ['passed','real_model','distinct_vault_keys','original_records_preserved','original_sync_work_preserved','urk_preserved','old_records_decrypted','post_upgrade_recall_checked','encrypted_tombstones_preserved','standalone_runtime_evidence','runtime_artifact_reused','normal_reopen_checked','post_upgrade_sync_checked']}
base.update({k:False for k in ['old_rpc_checked','forced_restart_checked','live_owner_restart_rejected','safe_restart_checked','supervised_worker_checked','in_process_checked','global_engine_preserved']})
base.update(seed_vault_versions=[1,3],historical_credential_migration_actor='fixture',host_credential_custody={'required':True,'cleanup_passed':True,'verified_accounts':[{'account':'main','vault_version':1,'urk_preserved':True},{'account':'alternate','vault_version':3,'urk_preserved':True}]},native_credential_cleanup={'passed':True,'remaining_entries':[]},upgrade_contract='standalone-v1',legacy_handoff_actor=None,coverage_scope='historical-database',host_checks_delegated_to='resident-concurrency',cloud_cleanup={'passed':True,'remaining_users':[]},runtime_mode='standalone_runtime',runtime_binary_sha256='a'*64,runtime_version='2.0.0-dev.24',runtime_identity_receipts=[{'pid':1}],binary_sha256='b'*64,engine='cpu',sequence=[{'account':a,'model_rows':{'embedder':{'status':'ok'},'model index':{'status':'ok'}}} for a in ['main','alternate','main']])
base['post_upgrade_sync']={k:True for k in ['original_urk_preserved','existing_keys_registered','source_push','independent_pull_decrypted','reverse_marker_source_pull','original_active_preserved','tombstones_propagated','pending_work_acknowledged']}
with tempfile.TemporaryDirectory() as d:
 root=pathlib.Path(d);old=root/'old';new=root/'new';old.mkdir();new.mkdir()
 summary={'target':'x86_64-unknown-linux-musl','candidate_sha256':'b'*64,'selected_sources':sorted(tags),'published_formal_sources':[t for t in tags if '-dev.' not in t],'database_dev_checkpoints':policy,'additional_draft_baselines':[]}
 (old/'published-upgrades.json').write_text(json.dumps(summary))
 (new/'published-upgrades.json').write_text(json.dumps(dict(summary,selected_sources=['v1.0.8'],diagnostic_sources=['v1.0.8'],passed=True,full_coverage=False,all_published_sources_covered=False)))
 for tag in tags:
  r=copy.deepcopy(base)
  if tag in policy:r['database_dev_checkpoint']={'tag':tag,'special_state_seeded':True,'special_state_preserved':True,'verified_accounts':['main','alternate'],'post_sync_special_state_preserved':True,'sync_verified_accounts':['main']}
  p=old/tag/'results';p.mkdir(parents=True);(p/'real-account-return-verification.json').write_text(json.dumps([r]))
 r=copy.deepcopy(base)
 p=new/'v1.0.8'/'results';p.mkdir(parents=True);f=p/'real-account-return-verification.json';f.write_text(json.dumps([r]));original=f.read_bytes()
 evidence=m(old,new,root/'merged','710e6b13ff588c02157d8d677e59e8f21c16beae','a'*64,'2.0.0-dev.24')
 assert len(evidence)==12 and all(x['contract']=='historical-385' for x in evidence)
 assert json.loads((root/'merged/published-upgrades.json').read_text())['sources'][0]['report'].endswith('/results/real-account-return-verification.json')
 for i,mutation in enumerate(['sync','failed','missing']):
  if mutation=='sync':bad=copy.deepcopy(r);del bad['post_upgrade_sync']['original_urk_preserved'];f.write_text(json.dumps([bad]))
  else:f.write_bytes(original)
  if mutation=='failed':bad=copy.deepcopy(base);bad['passed']=False;(old/'v1.0.7/results/real-account-return-verification.json').write_text(json.dumps([bad]))
  if mutation=='missing':(old/'v1.0.9/results/real-account-return-verification.json').unlink()
  try:m(old,new,root/('rejected'+str(i)),'710e6b13ff588c02157d8d677e59e8f21c16beae','a'*64,'2.0.0-dev.24')
  except AssertionError:pass
  else:raise AssertionError('Invalid source evidence accepted')
`],{encoding:'utf8'});
  assert.equal(mixed.status,0,mixed.stderr);
});

test('actual attester subprocess reads only main-bound mock APIs and rejects stale/foreign proofs before writing',async()=>{
  const directory=mkdtempSync(join(tmpdir(),'preparation-process-'));
  try{
    const assets=join(directory,'assets'),packs=join(directory,'packs'),reports=join(directory,'reports');
    for(const folder of [assets,packs,reports])mkdirSync(folder);
    const manifest=JSON.parse(readFileSync(new URL('../artifact-manifest.json',import.meta.url)));manifest.cliVersion=version;
    const files=manifest.targets.flatMap(t=>{
      const file=`rsrs-${t.triple}${t.triple.includes('windows')?'.exe':''}`,bytes=Buffer.from('synthetic CLI bytes; never executed');
      writeFileSync(join(assets,file),bytes);
      const metadata=`cli-build-${t.triple}.json`;
      writeFileSync(join(assets,metadata),JSON.stringify({schema_version:2,artifact_layout:manifest.artifactLayout,git_sha:sha,version,target:t.triple,
        binary_file:file,binary_size:bytes.length,binary_sha256:createHash('sha256').update(bytes).digest('hex'),producer:{run_id:'44276673815',run_attempt:1}}));
      return [file,metadata];
    });
    const inventory=files.map(file=>{const bytes=readFileSync(join(assets,file));return {file,size:bytes.length,sha256:createHash('sha256').update(bytes).digest('hex')};});
    const packages=[...manifest.targets.map(t=>t.pkg),manifest.npmScope].map((name,i)=>{
      const file=`pack-${i}.tgz`,bytes=Buffer.from(name);writeFileSync(join(packs,file),bytes);
      return {name,version,file,sha256:createHash('sha256').update(bytes).digest('hex')};
    });
    writeFileSync(join(packs,'source-version.json'),JSON.stringify({schema_version:1,git_sha:sha,version,packages}));
    const runtimeVersion=JSON.parse(readFileSync(new URL('../../.github/runtime-test-fixture.json',import.meta.url))).required;
    const candidate={schema:1,kind:'unpublished-cli-candidate',client2:{release:'v2.0.0-dev.6',source_sha:'f'.repeat(40)},source:{repository:source.repository,sha,version,run_id:44276673815,run_attempt:1},
      runtime:{repository:'risense-ai/respire-runtime',release_id:22,version:runtimeVersion,source_sha:'b'.repeat(40),producer:{run_id:91,run_attempt:2},
        assets:manifest.targets.flatMap((t,i)=>publishedAssetNames('runtime',t.triple).map((name,n)=>({id:i*3+n+1,name,size:64,sha256:'b'.repeat(64)})))}};
    const raw=publishedFullFixture(reports,{candidate,assets:inventory,packsFolder:packs});
    const inputs={'Cargo.lock':'synthetic locked dependencies','rust-toolchain.toml':'[toolchain]\nchannel="1.95.0"',
      '.github/runtime-test-fixture.json':JSON.stringify({required:runtimeVersion}),'.github/workflows/release.yml':'      - name: Bind fixtures to an independent official pinned Runtime\n        run: original-cloud-scope\n',
      '.github/workflows/release-validation.yml':'synthetic trusted build and package validation',
      '.github/workflows/release-native-validation.yml':'      - name: Verify and extract the release binary\n        run: original-native-scope\n','npm/artifact-manifest.json':JSON.stringify(manifest)};
    const state=join(directory,'state.json'),reads=join(directory,'reads'),output=join(directory,'proof.json'),mock=join(directory,'mock.mjs');
    writeFileSync(mock,`import cp from 'node:child_process';import fs from 'node:fs';import {syncBuiltinESMExports} from 'node:module';
const original=cp.execFileSync;cp.execFileSync=(command,a,options)=>{
 const s=JSON.parse(fs.readFileSync(process.env.MOCK_PREPARATION));
 if(s.continuation){
  if(command==='git'&&['merge-base','diff','ls-tree'].includes(a[0]))return '';
  if(command==='git'&&a[0]==='show'&&a[1]===s.consumerRun.head_sha+':.github/workflows/release-native-validation.yml')return s.inputs['.github/workflows/release-native-validation.yml'];
  if(command==='git'&&a[0]==='show'&&a[1]===s.consumerRun.head_sha+':.github/workflows/release-recovery3930.yml')return s.inputs['.github/workflows/release.yml'];
  if(command==='unzip')return a[0]==='-Z1'?'release-prepared.json\\n':JSON.stringify(s.proof);
  if(command==='gh'){
   const p=a.at(-1),base='repos/risense-ai/respire-cli/actions/';
   if(p===base+'runs/701')return JSON.stringify(s.consumerRun);
   if(p===base+'runs/701/attempts/1/jobs?per_page=100')return JSON.stringify([{jobs:s.current}]);
   if(p===base+'runs/44276673815/attempts/1/jobs?per_page=100')return JSON.stringify([{jobs:s.original}]);
   if(p===base+'runs/701/artifacts?per_page=100')return JSON.stringify([{artifacts:s.consumerArtifacts}]);
   if(p===base+'runs/44276673815/artifacts?per_page=100')return JSON.stringify([{artifacts:s.artifacts}]);
   if(p===base+'artifacts/9001/zip')return fs.readFileSync(s.zip);
  }
 }
 if(command==='git'){if(a.join(' ')==='rev-parse HEAD')return s.source.sha+'\\n';if(a[0]==='show'&&a[1].startsWith(s.source.sha+':')){const x=s.inputs[a[1].slice(41)];if(x===undefined)throw Error('Unknown source input');return options?.encoding==='utf8'?x:Buffer.from(x);}throw Error('Unexpected git action');}
 if(command!=='gh')return original(command,a,options);
 const p=a.at(-1),base='repos/risense-ai/respire-cli/actions/';if(a[0]!=='api'||a.some(x=>['--method','-X','POST','PATCH','PUT','DELETE'].includes(x)))throw Error('Non-read API action');fs.appendFileSync(process.env.MOCK_READS,p+'\\n');let r;
 if(p===base+'runs/44276673815')r=s.run;else if(p===base+'runs/600')r=s.ci;else if(p===base+'runs/44276673815/attempts/1/jobs?per_page=10')r=[{jobs:s.jobs}];else if(p===base+'runs/44276673815/artifacts?per_page=100')r=[{artifacts:s.artifacts}];else if(p===base+'workflows/ci.yml/runs?head_sha='+s.source.sha+'&per_page=100')r=[{workflow_runs:[s.ci]}];else throw Error('Unexpected API scope');return JSON.stringify(r);
};syncBuiltinESMExports();`);
    const env={...process.env,MOCK_PREPARATION:state,MOCK_READS:reads,GITHUB_REPOSITORY:source.repository,GITHUB_RUN_ID:'44276673815',GITHUB_RUN_ATTEMPT:'1',GITHUB_EVENT_NAME:'workflow_dispatch',
      GITHUB_REF:'refs/heads/main',GITHUB_SHA:sha,CLI_SHA:sha,CLI_VERSION:version,VALIDATION_PROFILE:'full',CANDIDATE_ASSETS:JSON.stringify(candidate)};
    const artifactNames=[...manifest.targets.map(t=>'cli-release-'+t.triple),'npm-release-validation','npm-release-packages'];
    let attestedIdentity;
    for(const [index,mutate] of [()=>{},s=>s.run.head_sha='f'.repeat(40),s=>s.ci.event='workflow_dispatch',s=>s.jobs[0].conclusion='skipped',s=>s.run.run_attempt=2,
      ()=>rmSync(join(reports,'client2-published-online-x86_64-pc-windows-msvc','report.json'))].entries()){
      const {context}=fixture();
      const value={...context,run:{...context.run,status:'in_progress'},inputs,
        jobs:[...raw.jobs.map(j=>({...j,started_at:time(0),completed_at:time(3)})),{id:900,name:'preparation-receipt',status:'in_progress',started_at:time(3)}],
        artifacts:artifactNames.map((name,i)=>({name,id:i+1,size_in_bytes:100,digest:'sha256:'+hash,expired:false,workflow_run:{id:44276673815,head_sha:sha}}))};
      mutate(value);writeFileSync(state,JSON.stringify(value));rmSync(output,{force:true});
      const result=spawnSync(process.execPath,['--import',pathToFileURL(mock).href,fileURLToPath(new URL('./release-preparation.mjs',import.meta.url)),'attest',assets,packs,output,reports],{env,encoding:'utf8',timeout:15000});
      if(index===0){
        assert.equal(result.status,0,result.stderr);const proof=JSON.parse(readFileSync(output));
        assert.deepEqual(proof.source,source);assert.equal(Object.keys(proof.identity.hashes).length,7);
        attestedIdentity=proof.identity;
        assert.equal(proof.assets.length,16);assert.equal(proof.packs.length,9);assert.equal(proof.state,'validated-unpublished');assert.equal(proof.full_result.gui_passed,true);
      }else{assert.notEqual(result.status,0);assert.equal(existsSync(output),false);}
    }
    // Continue only Windows: all original bytes/reports retain their actual producer identities.
    publishedFullFixture(reports,{candidate,assets:inventory,packsFolder:packs});
    const consumer={...source,workflow:recoveryWorkflow,run_id:'701',workflow_head_sha:'c'.repeat(40),producer:source};
    const original=raw.jobs.map((j,i)=>({...j,id:100+i,started_at:time(0),completed_at:time(3)}));
    const failed=original.find(j=>j.name===`native-regression / Native (${windowsTarget})`);failed.conclusion='failure';
    const current=[{...failed,id:1000,conclusion:'success',run_id:701,head_sha:consumer.workflow_head_sha},
      {id:1001,name:'preparation-receipt',status:'in_progress',started_at:time(3)}];
    const joined=recoveryJobs(original,current,source,consumer,manifest);
    const multi=structuredClone(original),additional=multi.filter(j=>j.name.startsWith('cloud-sweep (')&&['x86_64-unknown-linux-musl',windowsTarget,'x86_64-apple-darwin'].some(t=>j.name.endsWith(', '+t+')')))
      .concat(multi.filter(j=>['native-regression / Native (x86_64-apple-darwin)','native-regression / Native (aarch64-apple-darwin)'].includes(j.name)));
    for(const j of additional)j.conclusion='failure';
    const multiCurrent=[...current.slice(0,1),...additional.map((j,i)=>({...j,id:1100+i,conclusion:'success',run_id:701,head_sha:consumer.workflow_head_sha}))];
    assert.equal(recoveryJobs(multi,multiCurrent,source,consumer,manifest).jobs.length,25);
    assert.equal(recoveryJobs(multi,[],source,consumer,manifest,{planning:true}).jobs.length,19);
    assert.throws(()=>recoveryJobs(multi,multiCurrent.slice(1),source,consumer,manifest));
    assert.throws(()=>recoveryJobs(multi,[...multiCurrent,{...multiCurrent[0]}],source,consumer,manifest));
    const {context:base}=fixture();
    const run={...base.run,id:701,status:'in_progress',path:recoveryWorkflow,head_sha:consumer.workflow_head_sha};
    const producerRun={...base.run,status:'completed',conclusion:'failure'};
    validateRecoveryRuns(producerRun,run,source,consumer);
    const names=[...manifest.targets.map(t=>'cli-release-'+t.triple),'npm-release-validation',
      ...readdirSync(reports).filter(n=>!n.startsWith('published-assets-verification-'))];
    const replaced=['candidate-assets-','resident-concurrency-','published-upgrades-','client2-published-online-'].map(p=>p+windowsTarget);
    const metadata=(name,i,replace)=>({name,id:200+i,size_in_bytes:100,digest:'sha256:'+hash,expired:false,
      workflow_run:{id:replace?701:44276673815,head_sha:replace?consumer.workflow_head_sha:sha},created_at:time(1),updated_at:time(2)});
    const ctx={...base,source:consumer,manifest,run,...joined,original,current,assets:inventory,packs:preparedPacks(packs,source,manifest),identity:attestedIdentity,
      scripts:{producer_sha:sha,consumer_sha:consumer.workflow_head_sha,native_steps_sha256:createHash('sha256').update(inputs['.github/workflows/release-native-validation.yml']).digest('hex'),cloud_steps_sha256:cloudScope(inputs['.github/workflows/release.yml'],inputs['.github/workflows/release.yml']),unchanged_tree_sha256:createHash('sha256').update('').digest('hex')},
      artifacts:[...new Set(names)].map((n,i)=>metadata(n,i,false)),
      consumerArtifacts:replaced.map((n,i)=>metadata(n+'-recovery-701-1',100+i,true))};
    const options={evidenceOwners:joined.evidenceOwners,env:{...env,CLI_PRODUCER_RUN_ID:'44276673815',CLI_PRODUCER_ATTEMPT:'1',GITHUB_RUN_ID:'701',GITHUB_SHA:consumer.workflow_head_sha}};
    const full=()=>completeCandidate(candidate,inventory,reports,ctx.jobs,consumer,options);
    const mixed=recoveryJobs(multi,multiCurrent,source,consumer,manifest);
    assert.equal(completeCandidate(candidate,inventory,reports,mixed.jobs,consumer,{...options,evidenceOwners:mixed.evidenceOwners}).full_passed,true);
    const newNames=[];
    for(const j of multi.filter(j=>j.conclusion==='failure')){
      const t=j.name.startsWith('native-regression')?j.name.match(/Native \(([^)]+)\)/)[1]:j.name.match(/, ([^)]+)\)/)[1];
      if(j.name.startsWith('native-regression'))newNames.push(...['candidate-assets-','resident-concurrency-','published-upgrades-'].map(p=>p+t),...(t===windowsTarget?['client2-published-online-'+t]:[]));
      else newNames.push('base-release-sweep-'+t,...(t.includes('linux')?['release-sweep-'+t,'secret-service-profile-migration-'+t]:[]));
    }
    const mixedContext={...ctx,original:multi,current:multiCurrent,...mixed,consumerArtifacts:newNames.map((name,i)=>metadata(name+'-recovery-701-1',300+i,true))};
    const mixedAnchors=recoveryArtifacts(mixedContext);
    assert.equal(mixedAnchors.filter(a=>a.owner.run_id===701).length,newNames.length);
    for(const change of [c=>c.consumerArtifacts[0].workflow_run.id=44276673815,c=>c.consumerArtifacts[0].updated_at=time(4),c=>c.current[0].run_attempt++]){
      const c=structuredClone(mixedContext);change(c);assert.throws(()=>recoveryArtifacts(c));
    }
    const full_result=full();assert.equal(full_result.full_passed,true);assert.equal(full_result.historical_upgrades.length,8);
    assert.equal(Object.keys(joined.evidenceOwners).filter(n=>n.startsWith('cloud-sweep')).length,7);
    full_result.continuation={producer:source,consumer:{run_id:'701',run_attempt:1,sha:consumer.workflow_head_sha},scripts:ctx.scripts,
      artifacts:recoveryArtifacts(ctx),failed_jobs:[{id:failed.id,name:failed.name,run_attempt:failed.run_attempt}],
      failed_artifacts:replaced.map(name=>({...recoveryArtifact(ctx.artifacts,name,failed,{sha,run_id:44276673815,run_attempt:1},{failed:true}),reused:false}))};
    validateRecoveryEvidence(full_result,ctx);
    const proof=createPreparation({...ctx,assets:inventory,packs:preparedPacks(packs,source,manifest),full_result});
    ctx.run={...run,status:'completed',conclusion:'success'};
    Object.assign(ctx.jobs.at(-1),{status:'completed',conclusion:'success',completed_at:time(4)});
    assert.equal(validatePreparation(proof,ctx),proof);
    const publisher={repository:source.repository,workflow:source.workflow,run_id:'801',run_attempt:1,sha,version,release_id:901,workflow_head_sha:'e'.repeat(40)};
    const fencedNotes=fenceBody('Existing release notes',{schema:2,kind:'npm-version-fence',repository:source.repository,version,source_sha:sha,
      run_id:'801',first_attempt:1,created_at:time(4),phase:'fenced',package_names:proof.packs.map(p=>p.name),
      scoped_packages:proof.packs.map(p=>({name:p.name,version,integrity:'sha512-'+createHash('sha512').update(p.name).digest('base64'),shasum:'c'.repeat(40)}))});
    const imported={receipt:{preparation:proof},history:ctx};
    const rawReceiptBefore=JSON.stringify(proof);
    const evidenceBytes=recoveryPublicationEvidence(imported,candidate);
    const body=recoveryPublicationBody(fencedNotes,imported,publisher,candidate);
    assert.equal(JSON.stringify(proof),rawReceiptBefore,'Existing schema1 preparation must stay byte-for-byte unchanged');
    const publicPart={repository:source.repository,release_id:901,version,source_sha:sha,producer:{run_id:44276673815,run_attempt:1},
      assets:proof.assets.map((a,i)=>({id:i+1,name:a.file,size:a.size,sha256:a.sha256}))};
    const published={id:901,tag_name:'v'+version,draft:false,published_at:time(5),body};
    const publicAssets=[...publicPart.assets.map(a=>({...a,state:'uploaded',digest:'sha256:'+a.sha256})),
      {id:9901,name:recoveryProofName,size:evidenceBytes.length,state:'uploaded',digest:'sha256:'+createHash('sha256').update(evidenceBytes).digest('hex')}];
    assertReleaseAssets({...published,assets:publicAssets},{source:{sha,version},assets:publicPart.assets});
    for(const change of [a=>a.pop(),a=>a.push({...a[0],name:'unknown.json'}),a=>a.at(-1).digest='sha256:'+'0'.repeat(64)]){
      const a=structuredClone(publicAssets);change(a);assert.throws(()=>assertReleaseAssets({...published,assets:a},{source:{sha,version},assets:publicPart.assets}));
    }
    const publisherRun={id:801,run_attempt:1,head_sha:publisher.workflow_head_sha,head_branch:'main',event:'workflow_dispatch',
      head_repository:{full_name:source.repository},path:source.workflow,status:'completed',conclusion:'success',created_at:time(4)};
    const publicState={published,publicAssets,evidence:evidenceBytes.toString(),producerRun:{...producerRun,repository:{full_name:source.repository}},consumerRun:ctx.run,publisherRun,original:ctx.original,current:ctx.current,
      publicationJobs:['prepared-import','publication-ready','publish'].map(name=>({name,status:'completed',conclusion:'success',completed_at:time(6)}))};
    const fetchPublished=s=>async url=>{
      const p=new URL(url).pathname+new URL(url).search;let value;
      if(p.endsWith('/releases/901'))value=s.published;
      else if(p.endsWith('/releases/assets/9901'))return {status:200,arrayBuffer:async()=>Buffer.from(s.evidence)};
      else if(p.includes('/git/ref/tags/'))value={object:{type:'commit',sha}};
      else if(p.includes('/releases/901/assets?'))value=s.publicAssets;
      else if(p.includes('/contents/npm/artifact-manifest.json?')){
        const bytes=Buffer.from(JSON.stringify(manifest));value={type:'file',encoding:'base64',size:bytes.length,content:bytes.toString('base64'),
          sha:createHash('sha1').update(Buffer.concat([Buffer.from(`blob ${bytes.length}\0`),bytes])).digest('hex')};
      }else if(p.includes('/actions/runs/44276673815/attempts/1/jobs?'))value={jobs:s.original};
      else if(p.endsWith('/actions/runs/44276673815/attempts/1'))value=s.producerRun;
      else if(p.includes('/actions/runs/701/attempts/1/jobs?'))value={jobs:s.current};
      else if(p.endsWith('/actions/runs/701/attempts/1'))value=s.consumerRun;
      else if(p.includes('/actions/runs/801/attempts/1/jobs?'))value={jobs:s.publicationJobs};
      else if(p.endsWith('/actions/runs/801/attempts/1'))value=s.publisherRun;
      else throw Error('Unexpected public recovery request: '+p);
      return {status:200,json:async()=>value};
    };
    const verified=await inspectPublishedRelease(publicPart,{fetcher:fetchPublished(publicState)});
    validateRecoveredRuntime(verified.recovery,candidate.runtime);
    const wrongRuntime=structuredClone(candidate.runtime);wrongRuntime.assets[0].sha256='0'.repeat(64);assert.throws(()=>validateRecoveredRuntime(verified.recovery,wrongRuntime));
    assert.deepEqual(verified.producer,publicPart.producer);assert.equal(verified.recovery.consumer.run_id,'701');
    assert.equal(verified.recovery.full_result_sha256,undefined,'Public proof must not claim the private raw full-result digest');
    assert.deepEqual(JSON.parse(publicState.evidence).candidate,candidate);
    const privateCopy=structuredClone(proof);privateCopy.full_result.actual_processes[0].exe='PRIVATE_PATH_SENTINEL';privateCopy.full_result.actual_processes[0].account_id='PRIVATE_ACCOUNT_SENTINEL';
    privateCopy.full_result.historical_upgrades[0].unknown_private_text='PRIVATE_UNKNOWN_SENTINEL';
    for(const r of privateCopy.full_result.reports){
      if(r.artifact.startsWith('resident-concurrency-'))r.path=(r.path==='fixture-process-verification.json'?'native-fixture-bounds/':'resident-concurrency/')+r.path;
      if(r.artifact.startsWith('release-sweep-')){
        const nested={'outbox-coverage.json':'outbox/','ai-inject-coverage.json':'ai-inject/','legacy-vault-coverage.json':'legacy-vault/','interruption-coverage.json':'login-interruption/'};
        r.path='release-supplements/'+(nested[r.path]||'')+r.path;
      }
    }
    const safeBytes=recoveryPublicationEvidence({receipt:{preparation:privateCopy},history:ctx},candidate);
    assert(!safeBytes.includes(Buffer.from('PRIVATE_')));
    const unknownPath=structuredClone(proof);unknownPath.full_result.reports[0].path='unrecognized-private-directory/report.json';
    assert.throws(()=>recoveryPublicationEvidence({receipt:{preparation:unknownPath},history:ctx},candidate),/Non-whitelisted report path/);
    for(const mutate of [s=>s.published.body='',s=>s.publicAssets[0].digest='sha256:'+hash,
      s=>s.consumerRun.status='in_progress',s=>s.consumerRun.conclusion='failure',s=>s.consumerRun.run_attempt++,
      s=>s.original[0].conclusion='failure',s=>s.current[0].conclusion='failure',s=>s.publisherRun.head_branch='other',
      s=>s.publisherRun.status='in_progress',s=>s.publicationJobs[0].conclusion='failure',s=>s.publisherRun.created_at=time(2),
      s=>s.publicationJobs.at(-1).completed_at=time(4),s=>s.published.body=s.published.body.replace('rsrs-npm-write-fence:','foreign-fence:')]){
      const s=structuredClone(publicState);mutate(s);await assert.rejects(inspectPublishedRelease(publicPart,{fetcher:fetchPublished(s)}));
    }
    for(const change of [p=>p.producer.run_id++,p=>p.producer.run_attempt++,p=>p.source_sha='f'.repeat(40),p=>p.assets[0].sha256='f'.repeat(64)]){
      const p=structuredClone(publicPart);change(p);await assert.rejects(inspectPublishedRelease(p,{fetcher:fetchPublished(publicState)}));
    }
    for(const change of [p=>p.source.producer.run_attempt++,p=>p.source.producer.sha='f'.repeat(40),p=>p.assets[0].sha256='f'.repeat(64),
      p=>p.publisher.run_id='802',p=>p.source.workflow_head_sha='f'.repeat(40),p=>p.manifest_sha256='f'.repeat(64),p=>p.acceptance_sha256='f'.repeat(64)]){
      const s=structuredClone(publicState),match=s.published.body.match(/<!-- rsrs-cli3930-recovery:([A-Za-z0-9_-]+) -->/);
      const p=JSON.parse(Buffer.from(match[1],'base64url'));change(p);
      s.published.body=s.published.body.replace(match[1],Buffer.from(JSON.stringify(p)).toString('base64url'));
      await assert.rejects(inspectPublishedRelease(publicPart,{fetcher:fetchPublished(s)}));
    }
    for(const change of [e=>e.candidate.client2.source_sha='0'.repeat(40),e=>e.acceptance.reports[0].sha256='0'.repeat(64)]){
      const s=structuredClone(publicState),e=JSON.parse(s.evidence);change(e);s.evidence=JSON.stringify(e);
      await assert.rejects(inspectPublishedRelease(publicPart,{fetcher:fetchPublished(s)}));
    }
    // Execute the real inventory entry, including the failed original producer guard.
    const routes={},record=async(url,options)=>{
      const r=await fetchPublished(publicState)(url,options),key=url.replace('https://api.github.com/','');
      routes[key]=r.json?{json:await r.json()}:{binary:Buffer.from(await r.arrayBuffer()).toString('base64')};return r;
    };
    await inspectPublishedRelease(publicPart,{fetcher:record});
    const cliPrefix='repos/'+source.repository,runtime=candidate.runtime,rtPrefix='repos/'+runtime.repository;
    routes[cliPrefix+'/releases/tags/v'+version]={json:published};routes[cliPrefix+'/commits/v'+version]={json:{sha}};
    routes[cliPrefix+'/actions/runs/44276673815']={json:publicState.producerRun};
    routes[cliPrefix+'/releases/901/assets?per_page=100']={json:publicAssets};
    const rtAssets=runtime.assets.map(a=>({...a,state:'uploaded',digest:'sha256:'+a.sha256}));
    routes[rtPrefix+'/releases/tags/v'+runtime.version]={json:{id:runtime.release_id,tag_name:'v'+runtime.version,draft:false,published_at:time(0)}};
    routes[rtPrefix+'/releases/'+runtime.release_id]=routes[rtPrefix+'/releases/tags/v'+runtime.version];
    routes[rtPrefix+'/commits/v'+runtime.version]={json:{sha:runtime.source_sha}};
    routes[rtPrefix+'/git/ref/tags/v'+runtime.version]={json:{object:{type:'commit',sha:runtime.source_sha}}};
    routes[rtPrefix+'/actions/runs/'+runtime.producer.run_id]={json:{id:runtime.producer.run_id,run_attempt:runtime.producer.run_attempt,head_sha:runtime.source_sha,status:'completed',conclusion:'success',path:source.workflow,repository:{full_name:runtime.repository}}};
    routes[rtPrefix+'/actions/runs/'+runtime.producer.run_id+'/attempts/'+runtime.producer.run_attempt]=routes[rtPrefix+'/actions/runs/'+runtime.producer.run_id];
    routes[rtPrefix+'/releases/'+runtime.release_id+'/assets?per_page=100']={json:rtAssets};
    routes[rtPrefix+'/releases/'+runtime.release_id+'/assets?per_page=100&page=1']={json:rtAssets};
    const inventoryRoutes=join(directory,'inventory-routes.json'),inventoryMock=join(directory,'inventory-api.mjs');
    writeFileSync(inventoryRoutes,JSON.stringify(routes));
    writeFileSync(inventoryMock,`import cp from 'node:child_process';import fs from 'node:fs';import {syncBuiltinESMExports} from 'node:module';
const routes=JSON.parse(fs.readFileSync(process.env.INVENTORY_ROUTES));cp.execFileSync=(command,args,options={})=>{
 if(command!=='gh'||args[0]!=='api')throw Error('Unexpected inventory command');
 const key=args.find(a=>a.startsWith('repos/')),entry=routes[key];if(!entry)throw Error('Unexpected inventory API: '+key);
 const value=entry.binary?Buffer.from(entry.binary,'base64'):Buffer.from(args.includes('--jq')?entry.json.sha+'\\n':JSON.stringify(args.includes('--slurp')?[entry.json]:entry.json));
 return options.encoding?value.toString():value;
};syncBuiltinESMExports();`);
    const inventoryArgs=['--import',pathToFileURL(inventoryMock).href,fileURLToPath(new URL('../../scripts/create-published-assets.mjs',import.meta.url)),
      'v'+version,'44276673815','v'+runtime.version,String(runtime.producer.run_id)];
    const generate=()=>spawnSync(process.execPath,inventoryArgs,{env:{...process.env,INVENTORY_ROUTES:inventoryRoutes},encoding:'utf8',timeout:15000});
    const generated=generate();assert.equal(generated.status,0,generated.stderr);
    const generatedInventory=JSON.parse(generated.stdout);assert.deepEqual(generatedInventory.cli.producer,publicPart.producer);assert.deepEqual(generatedInventory.runtime,runtime);
    const originalRoutes=structuredClone(routes);
    for(const change of [r=>r[cliPrefix+'/actions/runs/701/attempts/1'].json.status='in_progress',
      r=>r[cliPrefix+'/releases/assets/9901'].binary=Buffer.from('{}').toString('base64')]){
      const changed=structuredClone(originalRoutes);change(changed);writeFileSync(inventoryRoutes,JSON.stringify(changed));assert.notEqual(generate().status,0);
    }
    for(const mutate of [c=>c.original.find(j=>j.name==='api-smoke').run_attempt++,c=>c.current[0].head_sha='f'.repeat(40),
      c=>c.original.find(j=>j.name.startsWith('cloud-sweep')).conclusion='failure',c=>c.current[0].status='in_progress',
      c=>c.original.find(j=>j.name.startsWith('validate / Release')).run_id=999]){
      const c=structuredClone(ctx);mutate(c);assert.throws(()=>recoveryJobs(c.original,c.current,source,consumer,manifest));
    }
    for(const mutate of [r=>r.run_attempt++,r=>r.head_sha='f'.repeat(40),r=>r.status='in_progress',r=>r.conclusion='success']){
      const r=structuredClone(producerRun);mutate(r);assert.throws(()=>validateRecoveryRuns(r,run,source,consumer));
    }
    const binding=ctx.artifacts[0],build=original.find(j=>j.name===`validate / Release (${manifest.targets[0].triple})`);
    recoveryArtifact(ctx.artifacts,binding.name,build,{sha,run_id:44276673815,run_attempt:1});
    for(const mutate of [a=>a.expired=true,a=>a.digest='bad',a=>a.workflow_run.head_sha='f'.repeat(40),a=>a.created_at=time(4)]){
      const a=structuredClone(binding);mutate(a);assert.throws(()=>recoveryArtifact([a],a.name,build,{sha,run_id:44276673815,run_attempt:1}));
    }
    for(const mutate of [p=>p.full_result.continuation.artifacts[0].digest='sha256:'+'f'.repeat(64),
      p=>p.full_result.continuation.consumer.run_attempt++,p=>p.full_result.continuation.scripts.unchanged_tree_sha256='f'.repeat(64),
      p=>p.full_result.continuation.artifacts.pop(),p=>p.full_result.continuation.failed_jobs[0].id++]){
      const p=structuredClone(proof);mutate(p);assert.throws(()=>validatePreparation(p,ctx));
    }
    const nativeFile=join(reports,'resident-concurrency-'+windowsTarget,'real-account-return-verification.json'),nativeBytes=readFileSync(nativeFile);
    const changed=JSON.parse(nativeBytes);changed[0].runtime_binary_sha256='f'.repeat(64);writeFileSync(nativeFile,JSON.stringify(changed));assert.throws(full);
    writeFileSync(nativeFile,nativeBytes);
    const upgradeFile=join(reports,'published-upgrades-'+windowsTarget,'published-upgrades.json'),upgradeBytes=readFileSync(upgradeFile);
    const upgrade=JSON.parse(upgradeBytes);upgrade.sources[0].passed=false;writeFileSync(upgradeFile,JSON.stringify(upgrade));assert.throws(full);
    writeFileSync(upgradeFile,upgradeBytes);
    for(const mutate of [e=>e.CLI_PRODUCER_ATTEMPT='2',e=>e.CLI_PRODUCER_RUN_ID='999',e=>e.CLI_SHA='f'.repeat(40)]){
      const e={...options.env};mutate(e);assert.throws(()=>completeCandidate(candidate,inventory,reports,ctx.jobs,consumer,{...options,env:e}));
    }
    const zip=join(directory,'bound.zip');
    const zipper=spawnSync(process.platform==='win32'?'py':'python3',[...(process.platform==='win32'?['-3']:[]),'-I','-c',
      'import zipfile,sys; z=zipfile.ZipFile(sys.argv[1],"w"); z.writestr("report.json", "{\\"passed\\":true}"); z.close()',zip],{encoding:'utf8'});
    assert.equal(zipper.status,0,zipper.stderr);
    const zipBytes=readFileSync(zip),anchor={id:'1',size:zipBytes.length,digest:'sha256:'+createHash('sha256').update(zipBytes).digest('hex')};
    const extracted=join(directory,'bound-extraction');
    downloadRecoveryArtifact(anchor,extracted,{transport:()=>zipBytes});assert.equal(JSON.parse(readFileSync(join(extracted,'report.json'))).passed,true);
    assert.throws(()=>downloadRecoveryArtifact({...anchor,digest:'sha256:'+hash},join(directory,'wrong-digest'),{transport:()=>zipBytes}));
    assert.throws(()=>downloadRecoveryArtifact({...anchor,size:1},join(directory,'wrong-size'),{transport:()=>zipBytes}));
    const proofFile=join(directory,'continuation-proof.json');writeFileSync(proofFile,JSON.stringify(proof));
    const proofZip=join(directory,'continuation-proof.zip');
    const zipped=spawnSync(process.platform==='win32'?'py':'python3',[...(process.platform==='win32'?['-3']:[]),'-I','-c',
      'import zipfile,sys; z=zipfile.ZipFile(sys.argv[1],"w",zipfile.ZIP_DEFLATED); z.write(sys.argv[2],"release-prepared.json"); z.close()',proofZip,proofFile],{encoding:'utf8'});
    assert.equal(zipped.status,0,zipped.stderr);
    const proofBytes=readFileSync(proofZip),proofMetadata={...metadata('release-prepared-701-1',0,true),id:9001,size_in_bytes:proofBytes.length,
      digest:'sha256:'+createHash('sha256').update(proofBytes).digest('hex')};
    const replay={...ctx,continuation:true,source,inputs,run:producerRun,consumerRun:ctx.run,ci:base.ci,proof,zip:proofZip,
      consumerArtifacts:[...ctx.consumerArtifacts,proofMetadata]};
    const reader='import {readPreparedRun} from '+JSON.stringify(new URL('./release-preparation.mjs',import.meta.url).href)+'; const r=readPreparedRun("701",'+JSON.stringify(sha)+','+JSON.stringify(version)+',"full"); if(r.receipt.source.producer.run_id!=="44276673815")throw Error("Wrong producer");';
    for(const [index,mutate] of [()=>{},s=>s.consumerRun.run_attempt++,s=>s.original[0].run_attempt++,s=>s.consumerArtifacts.at(-1).digest='sha256:'+hash].entries()){
      const s=structuredClone(replay);mutate(s);writeFileSync(state,JSON.stringify(s));
      const result=spawnSync(process.execPath,['--import',pathToFileURL(mock).href,'--input-type=module','-e',reader],{env:{...env,GH_TOKEN:'offline-fixture-only'},encoding:'utf8',timeout:15000});
      if(index===0)assert.equal(result.status,0,result.stderr);else assert.notEqual(result.status,0);
    }
    const gitFolder=join(directory,'script-contract');mkdirSync(gitFolder);
    const git=(...args)=>execFileSync('git',args,{cwd:gitFolder,encoding:'utf8'}).trim();
    git('init','-q');git('config','user.email','fixture@example.invalid');git('config','user.name','fixture');
    mkdirSync(join(gitFolder,'scripts'));writeFileSync(join(gitFolder,'scripts','fixture.py'),'original fixture\n');
    mkdirSync(join(gitFolder,'.github','workflows'),{recursive:true});writeFileSync(join(gitFolder,'.github','workflows','release-native-validation.yml'),inputs['.github/workflows/release-native-validation.yml']);
    writeFileSync(join(gitFolder,'.github','workflows','release.yml'),inputs['.github/workflows/release.yml']);
    git('add','.');git('commit','-qm','original');const originalSHA=git('rev-parse','HEAD');
    mkdirSync(join(gitFolder,'npm','scripts'),{recursive:true});writeFileSync(join(gitFolder,'npm','scripts','release-recovery3930.mjs'),'CI implementation\n');
    writeFileSync(join(gitFolder,'.github','workflows','release-recovery3930.yml'),inputs['.github/workflows/release.yml']);
    git('add','.');git('commit','-qm','CI');const ciSHA=git('rev-parse','HEAD');
    assert.match(recoveryScripts(originalSHA,ciSHA,{cwd:gitFolder}).unchanged_tree_sha256,/^[a-f0-9]{64}$/);
    assert.throws(()=>cloudScope(inputs['.github/workflows/release.yml'],inputs['.github/workflows/release.yml'].replace('original-cloud-scope','reduced-cloud-scope')),/Cloud scope, environment or commands changed/);
    writeFileSync(join(gitFolder,'.github','workflows','release-native-validation.yml'),inputs['.github/workflows/release-native-validation.yml'].replace('original-native-scope','reduced-native-scope'));
    git('add','.');git('commit','-qm','changed native scope');
    assert.throws(()=>recoveryScripts(originalSHA,git('rev-parse','HEAD'),{cwd:gitFolder}),/Native regression scope or commands changed/);
    writeFileSync(join(gitFolder,'.github','workflows','release-native-validation.yml'),inputs['.github/workflows/release-native-validation.yml']);
    writeFileSync(join(gitFolder,'scripts','fixture.py'),'changed fixture\n');git('add','.');git('commit','-qm','changed scope');
    assert.throws(()=>recoveryScripts(originalSHA,git('rev-parse','HEAD'),{cwd:gitFolder}),/fixture or unrelated CI source changed/);
    assert(readFileSync(reads,'utf8').trim().split('\n').every(p=>p.startsWith('repos/risense-ai/respire-cli/actions/')));
  }finally{rmSync(directory,{recursive:true,force:true});}
});

test('preparation requires full GUI and DB evidence and never upgrades critical or old incomplete proofs',()=>{
  const f=fixture();
  for(const change of [r=>delete r.full_result,r=>r.full_result.gui_passed=false,r=>r.full_result.full_passed=false,
    r=>r.full_result.historical_upgrades.pop(),r=>r.full_result.run_attempt++,r=>r.validation_profile='critical',
    r=>r.full_result.schema=1,r=>delete r.full_result.scope,r=>r.full_result.profile_import.status='passed',
    r=>r.validation.inventory.schema=1,r=>delete r.validation.inventory.scope]){
    const receipt=structuredClone(f.receipt);change(receipt);assert.throws(()=>validatePreparation(receipt,f.context));
  }
  assert.throws(()=>createPreparation({...f.context,run:{...f.context.run,status:'in_progress'},profile:'critical'}));
  const skipped=structuredClone(f.context);skipped.jobs.find(j=>j.name.startsWith('validate / Release')).conclusion='skipped';
  assert.throws(()=>validatePreparation(f.receipt,skipped));
});

test('binds the one ARM replay and all original Apple Silicon jobs to their exact owners',()=>{
  const p=approvedRecoveryProducer('44718206331');
  const producerOwner={run_id:Number(p.run_id),run_attempt:1,head_sha:p.sha};
  const arm='aarch64-unknown-linux-gnu';
  const native=t=>`native-regression / Native (${t})`;
  const all={targets:[...manifest.targets,{triple:arm}]};
  const completed={status:'completed',conclusion:'success'};
  const job=(name,id)=>({name,id,...producerOwner,...completed});
  const armFailed={...job(native(arm),136233485215),conclusion:'failure',steps:[
    {name:'Verify and extract the release binary',number:17,...completed},
    {name:'Upload candidate receipt',number:22,...completed},
  ]};
  const shards=Array.from({length:12},(_,i)=>job(`native-regression / Apple Silicon upgrade (v1.0.${i+6})`,200+i));
  const aggregate=job('native-regression / Apple Silicon upgrade aggregate',240);
  const original=[...all.targets.flatMap(({triple:t},i)=>[
    job(`validate / Release (${t})`,50+i),t===arm?armFailed:job(native(t),60+i),
    ...(t==='x86_64-unknown-linux-gnu'?[]:[job(`cloud-sweep (test-runner, ${t})`,70+i)]),
  ]),job('validate / npm-dry-run',80),job('api-smoke',81),...shards,aggregate,
  {...job('preparation-receipt',136275017543),conclusion:'failure'}];
  const harness='fbbe85b0aabd448d30f750d91ae488bda9284cea';
  const replay={id:44726670231,run_attempt:1,head_sha:harness,head_branch:'codex/cli-arm64-gnu-native-replay-44718206331',
    head_repository:{full_name:p.repository},path:'.github/workflows/dev-sweep.yml',event:'workflow_dispatch',...completed};
  const replayJob={name:native(arm),id:136255766094,run_id:replay.id,run_attempt:1,head_sha:harness,...completed,steps:[
    'Require real native Linux ARM64 hardware',
    'Verify exact original CLI and official Runtime for this diagnostic replay',
    'Install and verify the official pinned standalone Runtime',
    'Verify OS autostart registration from verified release bytes',
    'Install and probe BGE CPU inference',
    'Verify selected formal release and database DEV upgrades',
    'Verify resident foreground and background inference under concurrent CLI load',
  ].map(name=>({name,...completed}))};
  const rJobs=[replayJob,{...replayJob,name:'verify-selection',id:136255731145}];
  const consumer={...p,workflow:recoveryWorkflow,run_id:'701',workflow_head_sha:'c'.repeat(40),producer:p};
  const run=(old=original,now=[],proof=replayJob)=>recoveryJobs(old,now,p,consumer,all,{armReplayEvidence:proof});
  assert.equal(validateArmReplay(replay,rJobs),replayJob);
  const joined=run();
  // Empty workflow matrix from recovery run 44736281076, including its synthetic job clocks.
  const skippedCloud={
    id:136288596510,run_id:44736281076,run_attempt:1,head_sha:'36dc605c481480554d2f31dbdc5d25a2f3326bea',
    name:'cloud-sweep (${{ matrix.os }}, ${{ matrix.target }})',status:'completed',conclusion:'skipped',steps:[],
    started_at:'2026-11-20T12:30:30Z',completed_at:'2026-11-20T12:30:29Z',
  };
  assert.deepEqual(run(original,[skippedCloud]),joined);
  for(const invalid of [
    {...skippedCloud,name:'cloud-sweep (ubuntu-24.04-arm, aarch64-unknown-linux-gnu)'},
    {...skippedCloud,status:'in_progress'},
    {...skippedCloud,conclusion:'success'},
    {...skippedCloud,steps:undefined},
    {...skippedCloud,steps:[{name:'Set up job',status:'completed',conclusion:'success'}]},
  ])assert.throws(()=>run(original,[invalid]),/cannot be combined/);
  assert.throws(()=>run(original,[skippedCloud,skippedCloud]),/cannot be combined/);
  assert.equal(joined.evidenceOwners[native(arm)].run_id,replay.id);
  assert.equal(joined.evidenceOwners[aggregate.name].run_id,Number(p.run_id));
  assert.ok(shards.every(s=>joined.evidenceOwners[s.name].run_attempt===1));
  assert.throws(()=>approvedRecoveryProducer('44731065057'),/Unapproved/);
  assert.throws(()=>validateArmReplay({...replay,run_attempt:2},rJobs));
  assert.throws(()=>validateArmReplay({...replay,head_sha:p.sha},rJobs));
  assert.throws(()=>validateArmReplay(replay,[{...replayJob,steps:replayJob.steps.slice(0,-1)},rJobs[1]]));
  assert.throws(()=>run(original,[],{...replayJob,id:9}));
  assert.throws(()=>run(original,[replayJob]),/cannot be combined/);
  assert.throws(()=>run(original.filter(j=>j!==aggregate)),/aggregate/);
  assert.throws(()=>run(original.filter(j=>j!==shards[0])),/twelve/);
  assert.throws(()=>run(original.map(j=>j===aggregate?{...j,run_attempt:2}:j)));
  assert.throws(()=>run(original.map(j=>j.name==='api-smoke'?{...j,conclusion:'failure'}:j)),/exactly/);
  assert.throws(()=>run(original.map(j=>j===armFailed?{...j,steps:j.steps.slice(1)}:j)),/required step/);
});

test('requires the original ARM build and standard receipt to match the unmodified replay proof',()=>{
  const p=approvedRecoveryProducer('44718206331');
  const owner={run_id:Number(p.run_id),run_attempt:1,sha:p.sha};
  const source={...owner,version:p.version};
  const target='aarch64-unknown-linux-gnu';
  const harness={sha:'fbbe85b0aabd448d30f750d91ae488bda9284cea',run_id:'44726670231',run_attempt:'1'};
  const candidate={runtime:{version:'2.0.0-dev.28'}};
  const manifest_sha256=createHash('sha256').update(JSON.stringify(candidate)).digest('hex');
  const anchor=(prefix,digest,conclusion)=>({name:prefix+target,digest:'sha256:'+digest,owner,conclusion});
  const build=anchor('cli-release-','edba437b55930e36c7241bd57a43f1f614d9400b1b95cb8d70bd7a7f299ecb01','success');
  const prior=anchor('candidate-assets-','ef4af3e83cf138f2f9707da4b9fc883b72ff48cc71c683d0de6536d9841e4066','failure');
  const original={kind:'candidate-assets-verification',target,manifest_sha256,candidate,
    assets_verified:true,payloads_verified:true,runtime_producer:{run_id:39},
    payload_identity:{harness_sha:p.sha,cli_binary_sha256:'1'.repeat(64),runtime_binary_sha256:'2'.repeat(64)}};
  const replay={schema:1,kind:'native-replay-inputs',diagnostic_only:true,target,source,harness,candidate,manifest_sha256,
    build:{...build,owner:source},prior:{...prior,owner:source},runtime_producer:original.runtime_producer,
    payload_identity:{...original.payload_identity,harness_sha:harness.sha}};
  const check=(input=replay,previous=original)=>validateArmReplayInputs(input,previous,
    {...build,logical_name:build.name},{...prior,logical_name:prior.name},candidate);
  check();
  assert.throws(()=>check({...replay,diagnostic_only:false}));
  assert.throws(()=>check({...replay,prior:{...replay.prior,digest:build.digest}}));
  assert.throws(()=>check({...replay,kind:'candidate-assets-verification'}));
  assert.throws(()=>check({...replay,runtime_producer:{run_id:40}}));
  assert.throws(()=>check({...replay,payload_identity:{...replay.payload_identity,cli_binary_sha256:'3'.repeat(64)}}));
  assert.throws(()=>check(replay,{...original,assets_verified:false}));
});
