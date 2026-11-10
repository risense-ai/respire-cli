import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {runInNewContext} from 'node:vm';
import {spawnSync} from 'node:child_process';
import path from 'node:path';
const workflow=readFileSync(new URL('../../.github/workflows/dev-sweep.yml',import.meta.url),'utf8');
const hash=value=>createHash('sha256').update(value).digest('hex');
const step=name=>workflow.split(`      - name: ${name}\n`)[1]?.split(/\n      - (?:name|uses):/)[0];
const binding=step("Bind diagnostic fixtures to the CLI's official pinned Runtime");
const script=binding.split("<<'NODE'\n")[1].split('\n          NODE')[0].replace(/^          /gm,'');
test('diagnostic wiring preserves dispatch, permissions, source producer checks and API job',()=>{
  // Exact pre-existing trust boundaries; full Release checks are not weakened by this repair.
  assert.equal(hash(workflow.split('jobs:\n')[0]),'251cbc82190bc45915963d50bc3ecd83cb1e4bfe72f9bed86ee33faf0b2c347a');
  assert.equal(hash(step('Verify the original release build')),'c07d866f172e6c28e49889fc0f3d8d5fa1ad6bf9ecb26724e4db35d2e2bbabfe');
  assert.equal(hash(step('Verify and extract the original binary')),'2cf493f2afd7eae32aa0f49ec56815a50dffafb00d64015d38b0b8a2c10ecc8b');
  assert.equal(hash(workflow.split('\n  api-smoke:\n')[1]),'88aebc2bef3afed3d4426e2aa9fcffb3ecad36bd973084af62af28284c732718');
  assert.match(workflow,/required=\[\.\.\.m.targets.map\(t=>`Release \(\$\{t.triple\}\)`\),'npm-dry-run'\]/);
  assert.match(workflow,/run.head_sha!==sha/);
  assert.match(workflow,/j.conclusion==='success'/);
  assert.match(workflow,/Choose one diagnostic scope/);
  assert.doesNotMatch(workflow,/ARTIFACT_SOURCE: published-assets|RSRS_ARTIFACT_SOURCE:|continue-on-error:/);
});
test('standalone identity precedes credentials and every dependent fixture is fail-closed',()=>{
  for(const text of ['ARTIFACT_SOURCE: build','VALIDATION_PROFILE: full','RSRS_RUNTIME_TRIPLE: ${{ matrix.target }}']) assert(workflow.includes(text));
  const ordered=['id: verified_artifact','id: supplement_python','id: standalone_runtime','id: native_credentials','name: Sweep the exact CI binary'];
  for(let i=1;i<ordered.length;i++)assert(workflow.indexOf(ordered[i-1])<workflow.indexOf(ordered[i]));
  assert.match(binding,/steps.verified_artifact.outcome == 'success'/);
  assert.match(binding,/steps.supplement_python.outcome == 'success'/);
  assert.match(binding,/RSRS_DATA_DIR: \$\{\{ runner.temp \}\}\/diagnostic-runtime-proof/);
  assert.match(binding,/node scripts\/ci-install-pinned-runtime.mjs "\$exe"/);
  for(const name of ['Sweep the exact CI binary','Verify all supplementary CLI contracts','Verify historical Secret Service profile migration','Verify native encrypted profile migration','Verify real legacy authentication salt migration','Diagnose runtime contracts without a full release claim']){
    const condition=step(name).split('\n')[0];
    assert(condition.includes("steps.standalone_runtime.outcome == 'success'"),name);
    assert(condition.includes("runner.os != 'Linux' || steps.native_credentials.outcome == 'success'"),name);
    const evaluate=(runtime,credentials,os='Linux')=>runInNewContext(condition.slice(condition.indexOf('${{')+3,condition.lastIndexOf('}}')),{cancelled:()=>false,inputs:{local_api_only:name.startsWith('Diagnose'),auth_salt_only:name.startsWith('Verify real')},runner:{os},steps:{standalone_runtime:{outcome:runtime},native_credentials:{outcome:credentials},supplement_python:{outcome:'success'}}});
    for(const runtime of ['failure','skipped','cancelled']) assert.equal(evaluate(runtime,'success'),false,name);
    for(const credentials of ['failure','skipped','cancelled']) assert.equal(evaluate('success',credentials),false,name);
    if(name!=='Verify native encrypted profile migration')assert.equal(evaluate('success','success'),true,name);
    else assert.equal(evaluate('success','skipped','Windows'),true,name);
  }
});
test('Linux base and supplements use separate unlocked private credential wrappers and preserve failures',()=>{
  const deps=step('Prepare persistent native credentials for diagnostic fixtures');
  for(const value of ['dbus-x11 gnome-keyring','SecretStorage==3.3.3','jeepney==0.9.0','cryptography==46.0.3','psutil==7.1.0'])assert(deps.includes(value));
  for(const [name,root,command] of [['Sweep the exact CI binary','base-sweep-credentials','-- pwsh -NoProfile -File scripts/dev-release-sweep.ps1'],['Verify all supplementary CLI contracts','supplement-credentials','-- python3 scripts/dev-smoke-supplements.py']]){
    const block=step(name);
    assert(block.includes('dbus-run-session -- env RSRS_SS_FIXTURE_BUS=private python3 scripts/dev-secret-service-keyring-selftest.py'));
    assert(block.includes(root));assert(block.includes('--timeout 6600'));assert(block.includes(command));
    assert(workflow.includes(`${root}/business-keyring-selftest.json`));
  }
  assert.match(step('Sweep the exact CI binary'),/if \(\$LASTEXITCODE -ne 0\) \{ exit \$LASTEXITCODE \}/);
  assert.match(step('Verify all supplementary CLI contracts'),/set -euo pipefail/);
  assert.match(workflow,/standalone-diagnostic-identity.json/);
});
function simulate(change=()=>{}){
  const state={pin:{required:'2.0.0-dev.6',accept:'>=2.0.0-dev.6,<3.0.0'},metadata:{git_sha:'c'.repeat(40),version:'1.2.3-dev.4',producer:{run_id:42,run_attempt:2},target:'x86_64-unknown-linux-musl',binary_sha256:hash('CLI')},inventory:{command:'runtime.list',status:'ok',summary:{required:'2.0.0-dev.6',accept:'>=2.0.0-dev.6,<3.0.0'}},version:{command:'version',status:'ok',summary:{version:'1.2.3-dev.4'}},display:'rsrs 1.2.3-dev.4',cli:'CLI',runtime:'RUNTIME',runtimePath:'/temp/proof/runtime/2.0.0-dev.6/rsrs-runtime'};
  state.runtimeMetadata={schema_version:2,runtime_version:state.pin.required,target_triple:state.metadata.target,binary_sha256:hash(state.runtime),source_commit:'d'.repeat(40)};
  state.receipt={version:state.pin.required,sha256:hash(state.runtime),release:{metadata_json:JSON.stringify(state.runtimeMetadata)}};
  state.receipt.release.metadata_sha256=hash(state.receipt.release.metadata_json);
  change(state);
  const env={RSRS_DATA_DIR:'/temp/proof',RUNNER_TEMP:'/temp',RSRS_RUNTIME_TRIPLE:state.metadata.target,CLI_SHA:'c'.repeat(40),CLI_RUN_ID:'42',GITHUB_SHA:'a'.repeat(40),GITHUB_RUN_ID:'43',GITHUB_RUN_ATTEMPT:'1',GH_TOKEN:'synthetic-secret',SERVICE_API_KEY:'synthetic-secret',RSRS_RUNTIME_BIN:'untrusted'};
  let report;
  const fs={realpathSync:p=>p==='cli'?'/cli':state.runtimePath,readFileSync:p=>p==='runtime-pin.json'?JSON.stringify(state.pin):p.startsWith('validated-cli/')?JSON.stringify(state.metadata):p==='/temp/proof/runtime.json'?JSON.stringify(state.receipt):p==='/cli'?state.cli:state.runtime,writeFileSync:(p,text)=>{assert.equal(p,'/temp/standalone-diagnostic-identity.json');report=JSON.parse(text);}};
  const cp={execFileSync:(binary,args,options)=>{assert.equal(binary,'/cli');assert.equal(options.timeout,30000);for(const key of ['GH_TOKEN','SERVICE_API_KEY','RSRS_RUNTIME_BIN'])assert.equal(options.env[key],undefined);assert.equal(options.env.HOME,'/temp/proof/home');return args.includes('list')?JSON.stringify(state.inventory):args.includes('v')?JSON.stringify(state.version):state.display;}};
  runInNewContext(script,{require:name=>({fs,path,child_process:cp,'assert/strict':assert,crypto:{createHash}})[name],process:{argv:['node','-','cli'],env,platform:'linux'}});
  return report;
}
test('executed identity body separates H from C and records only verified installation proof',()=>{
  const report=simulate();assert.equal(report.harness_sha,'a'.repeat(40));assert.equal(report.cli_source_sha,'c'.repeat(40));assert.equal(report.producer.run_id,42);assert.equal(report.producer.run_attempt,2);
  assert.equal(report.cli.binary_sha256,hash('CLI'));assert.equal(report.runtime.binary_sha256,hash('RUNTIME'));
  assert.equal(report.diagnostic_only,true);assert.equal(report.full_acceptance,false);assert.equal(report.publication_reusable,false);
  assert(!JSON.stringify(report).includes('synthetic-secret'));
});
test('executed identity body rejects mismatched pin, producer, C version, hashes and Runtime proof',()=>{
  for(const change of [s=>s.inventory.summary.required='2.0.0-dev.5',s=>s.inventory.summary.accept='*',s=>s.inventory.status='fail',s=>s.metadata.git_sha='a'.repeat(40),s=>s.metadata.producer.run_id=41,s=>s.cli+='changed',s=>s.version.summary.version='1.2.3-dev.5',s=>s.version.status='fail',s=>s.display+='wrong',s=>s.receipt.version='2.0.0-dev.5',s=>s.receipt.release.metadata_sha256='0'.repeat(64),s=>s.runtime+='changed',s=>s.runtimePath='/cli',s=>{s.runtimeMetadata.binary_sha256='0'.repeat(64);s.receipt.release.metadata_json=JSON.stringify(s.runtimeMetadata);s.receipt.release.metadata_sha256=hash(s.receipt.release.metadata_json);},s=>{s.runtimeMetadata.target_triple='wrong';s.receipt.release.metadata_json=JSON.stringify(s.runtimeMetadata);s.receipt.release.metadata_sha256=hash(s.receipt.release.metadata_json);},s=>{s.runtimeMetadata.runtime_version='wrong';s.receipt.release.metadata_json=JSON.stringify(s.runtimeMetadata);s.receipt.release.metadata_sha256=hash(s.receipt.release.metadata_json);}])assert.throws(()=>simulate(change));
});
test('all bash step bodies parse offline',()=>{
  for(const block of workflow.split(/\n      - (?:name|uses):/)){
    if(!block.includes('shell: bash')||!block.includes('        run: |\n'))continue;
    const body=block.split('        run: |\n')[1].replace(/^          /gm,'');
    const result=spawnSync('bash',['-n'],{input:body,encoding:'utf8',timeout:5000});assert.equal(result.status,0,result.stderr);
  }
});
