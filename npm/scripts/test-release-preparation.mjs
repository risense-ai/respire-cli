import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,writeFileSync,rmSync,readFileSync,mkdirSync,existsSync,readdirSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {createHash} from 'node:crypto';
import {spawnSync,execFileSync} from 'node:child_process';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {publishedFullFixture} from './full-report-fixture.mjs';
import {publishedAssetNames,inspectPublishedRelease} from './extract-artifact.mjs';
import {createPreparation,validatePreparation,preparedAssets,preparedPacks,validatePreparationRun} from './release-preparation.mjs';
import {completeCandidate} from './candidate-artifact.mjs';
import {fenceBody} from './publication-fence.mjs';
import {recoveryWorkflow,windowsTarget,validateRecoveryRuns,recoveryJobs,recoveryArtifact,recoveryArtifacts,
  downloadRecoveryArtifact,validateRecoveryEvidence,recoveryScripts,cloudScope,recoveryPublicationBody} from './release-recovery3930.mjs';

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

test('Release attests all full candidate consumers and publishes only verified imported bytes',()=>{
  const release=readFileSync(new URL('../../.github/workflows/release.yml',import.meta.url),'utf8').replace(/\r\n/g,'\n');
  assert.match(release,/needs: \[plan, validate, native-regression, cloud-sweep, api-smoke\]/);
  assert.match(release,/release-preparation.mjs attest release-assets full-reports\/npm-release-packages release-prepared.json full-reports/);
  assert.match(release,/prepared_binary_run: \$\{\{ steps.prepared.outputs.prepared_binary_run \}\}/);
  assert.equal((release.match(/run-id: \$\{\{ needs.plan.outputs.prepared_binary_run \}\}/g)||[]).length,2);
  assert.equal((release.match(/git archive "\$GITHUB_SHA" npm\/scripts\/\{release-recovery3930,release-preparation,candidate-artifact,extract-artifact,publication-acceptance\}.mjs \| tar -x/g)||[]).length,4);
  const continuation=readFileSync(new URL('../../.github/workflows/release-recovery3930.yml',import.meta.url),'utf8');
  assert.match(continuation,/uses: \.\/.github\/workflows\/release-native-validation.yml/);
  assert.match(continuation,/validation_profile: full/);
  assert.doesNotMatch(continuation,/contents: write|actions: write|GITHUB_(SHA|RUN_ID|RUN_ATTEMPT):|gh run rerun|gh workflow run/);
  const publisher=release.split('\n  publish:\n')[1];
  assert.match(publisher,/needs.prepared-import.result == 'success'/);
  assert.match(publisher,/needs.publication-ready.result == 'success'/);
  assert.match(publisher,/--reuse-packs npm\/release-packages --export-packs npm\/publication-packages/);
  assert.doesNotMatch(publisher,/--pack npm\/publication-packages/);
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
    const runtimeVersion=JSON.parse(readFileSync(new URL('../../runtime-pin.json',import.meta.url))).required;
    const candidate={schema:1,kind:'unpublished-cli-candidate',client2:{release:'v2.0.0-dev.6',source_sha:'f'.repeat(40)},source:{repository:source.repository,sha,version,run_id:44276673815,run_attempt:1},
      runtime:{repository:'risense-ai/respire-runtime',release_id:22,version:runtimeVersion,source_sha:'b'.repeat(40),producer:{run_id:91,run_attempt:2},
        assets:manifest.targets.flatMap((t,i)=>publishedAssetNames('runtime',t.triple).map((name,n)=>({id:i*3+n+1,name,size:64,sha256:'b'.repeat(64)})))}};
    const raw=publishedFullFixture(reports,{candidate,assets:inventory,packsFolder:packs});
    const inputs={'Cargo.lock':'synthetic locked dependencies','rust-toolchain.toml':'[toolchain]\nchannel="1.95.0"',
      'runtime-pin.json':JSON.stringify({required:runtimeVersion}),'.github/workflows/release.yml':'      - name: Bind fixtures to an independent official pinned Runtime\n        run: original-cloud-scope\n',
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
    const body=recoveryPublicationBody(fencedNotes,{receipt:{preparation:proof},history:ctx},publisher);
    const publicPart={repository:source.repository,release_id:901,version,source_sha:sha,producer:{run_id:44276673815,run_attempt:1},
      assets:proof.assets.map((a,i)=>({id:i+1,name:a.file,size:a.size,sha256:a.sha256}))};
    const published={id:901,tag_name:'v'+version,draft:false,published_at:time(5),body};
    const publicAssets=publicPart.assets.map(a=>({...a,state:'uploaded',digest:'sha256:'+a.sha256}));
    const publisherRun={id:801,run_attempt:1,head_sha:publisher.workflow_head_sha,head_branch:'main',event:'workflow_dispatch',
      head_repository:{full_name:source.repository},path:source.workflow,status:'completed',conclusion:'success',created_at:time(4)};
    const publicState={published,publicAssets,producerRun:{...producerRun,repository:{full_name:source.repository}},consumerRun:ctx.run,publisherRun,original:ctx.original,current:ctx.current,
      publicationJobs:['prepared-import','publication-ready','publish'].map(name=>({name,status:'completed',conclusion:'success',completed_at:time(6)}))};
    const fetchPublished=s=>async url=>{
      const p=new URL(url).pathname+new URL(url).search;let value;
      if(p.endsWith('/releases/901'))value=s.published;
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
    assert.deepEqual(verified.producer,publicPart.producer);assert.equal(verified.recovery.consumer.run_id,'701');
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
      p=>p.publisher.run_id='802',p=>p.source.workflow_head_sha='f'.repeat(40)]){
      const s=structuredClone(publicState),match=s.published.body.match(/<!-- rsrs-cli3930-recovery:([A-Za-z0-9_-]+) -->/);
      const p=JSON.parse(Buffer.from(match[1],'base64url'));change(p);
      s.published.body=s.published.body.replace(match[1],Buffer.from(JSON.stringify(p)).toString('base64url'));
      await assert.rejects(inspectPublishedRelease(publicPart,{fetcher:fetchPublished(s)}));
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
    assert.throws(()=>recoveryScripts(originalSHA,git('rev-parse','HEAD'),{cwd:gitFolder}),/Windows native scope or commands changed/);
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
