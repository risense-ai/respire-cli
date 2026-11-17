import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {runInNewContext} from 'node:vm';
import {spawnSync} from 'node:child_process';
import path from 'node:path';
const workflow=readFileSync(new URL('../../.github/workflows/dev-sweep.yml',import.meta.url),'utf8').replace(/\r\n/g,'\n');
const sweep=readFileSync(new URL('../../scripts/dev-release-sweep.ps1',import.meta.url),'utf8').replace(/\r\n/g,'\n');
const hash=value=>createHash('sha256').update(value).digest('hex');
const step=name=>workflow.split(`      - name: ${name}\n`)[1]?.split(/\n      - (?:name|uses):/)[0];
const binding=step("Bind diagnostic fixtures to the CLI's official pinned Runtime");
const script=binding.split("<<'NODE'\n")[1].split('\n          NODE')[0].replace(/^          /gm,'');
test('diagnostic wiring preserves dispatch, permissions, source producer checks and API job',()=>{
  // Exact pre-existing trust boundaries; full Release checks are not weakened by this repair.
  const dispatchInput="      business_only:\n        description: Run only synthetic cross-device business diagnostics; never release acceptance\n        type: boolean\n        default: false\n";
  const callInput="      business_only:\n        type: boolean\n        default: false\n";
  const dispatchRuntime="      runtime_sha:\n        description: Exact published Runtime source SHA, required for business diagnostics\n        required: false\n        type: string\n";
  const callRuntime="      runtime_sha:\n        required: false\n        type: string\n";
  const dispatchHistory="      history_sources:\n        description: Diagnostic historical DB tags separated by commas (latest resolves the latest formal); requires database_sync_only\n        type: string\n        default: ''\n";
  const callHistory="      history_sources:\n        type: string\n        default: ''\n";
  const header=workflow.split('jobs:\n')[0];
  for(const input of [dispatchInput,callInput,dispatchRuntime,callRuntime,dispatchHistory,callHistory])assert(header.includes(input));
  assert.equal(hash(header.replace(dispatchInput,'').replace(callInput,'').replace(dispatchRuntime,'').replace(callRuntime,'').replace(dispatchHistory,'').replace(callHistory,'')),'e22044c490d5efe81a4fdddd47d146b565302d1cecd112ee09aeb6115e65037b');
  const historyGuard=workflow.split('\n').find(line=>line.includes("throw new Error(\"Historical sources require database_sync_only\")")).trim().slice("node -e '".length,-1);
  assert.throws(()=>runInNewContext(historyGuard,{process:{env:{HISTORY_SOURCES:'latest',DATABASE_SYNC_ONLY:'false'}}}),/Historical sources require/);
  assert.doesNotThrow(()=>runInNewContext(historyGuard,{process:{env:{HISTORY_SOURCES:'latest',DATABASE_SYNC_ONLY:'true'}}}));
  assert.equal(hash(step('Verify the original release build')),'c07d866f172e6c28e49889fc0f3d8d5fa1ad6bf9ecb26724e4db35d2e2bbabfe');
  assert.equal(hash(step('Verify and extract the original binary')),'2cf493f2afd7eae32aa0f49ec56815a50dffafb00d64015d38b0b8a2c10ecc8b');
  const api=workflow.split('\n  api-smoke:\n')[1];
  assert(api.includes('if: ${{ !inputs.database_sync_only && !inputs.business_only }}'));
  assert.equal(hash(api.replace('if: ${{ !inputs.database_sync_only && !inputs.business_only }}','if: ${{ !inputs.database_sync_only }}')),'f5f71f1f9d8e808add8ee4143b67b8b6c070099887bc4a2216cb9c7dec96402b');
  assert.match(workflow,/required=\[\.\.\.m.targets.map\(t=>`Release \(\$\{t.triple\}\)`\),'npm-dry-run'\]/);
  assert.match(workflow,/run.head_sha!==sha/);
  assert.match(workflow,/j.conclusion==='success'/);
  assert.match(workflow,/Choose one diagnostic scope/);
  assert.doesNotMatch(workflow,/ARTIFACT_SOURCE: published-assets|RSRS_ARTIFACT_SOURCE:|continue-on-error:/);

  const expression=line=>line.match(/\$\{\{ (.*) \}\}/)[1];
  const evaluate=(line,inputs)=>runInNewContext(expression(line),{inputs,cancelled:()=>false,
    runner:{os:'Linux'},matrix:{target:'x86_64-unknown-linux-musl'},steps:{supplement_python:{outcome:'success'},standalone_runtime:{outcome:'success'},native_credentials:{outcome:'success'}}});
  const job=name=>workflow.split(`\n  ${name}:\n`)[1].split('\n')[0];
  const normal={api_only:false,local_api_only:false,database_sync_only:false,business_only:false};
  const business={...normal,business_only:true};
  assert.equal(evaluate(job('sweep'),normal),true);assert.equal(evaluate(job('api-smoke'),normal),true);
  assert.equal(evaluate(job('sweep'),business),true);assert.equal(evaluate(job('api-smoke'),business),false);
  assert.equal(evaluate(job('sweep'),{...business,api_only:true}),true);
  assert.equal(evaluate(step('Sweep the exact CI binary').split('\n')[0],business),true);
  for(const name of ['Verify all supplementary CLI contracts','Verify historical Secret Service profile migration','Verify native encrypted profile migration'])
    assert.equal(evaluate(step(name).split('\n')[0],business),false,name);
  assert.match(workflow,/inputs\.business_only\) && '\[\{"os":"ubuntu-latest","target":"x86_64-unknown-linux-musl"\}\]'/);
  const guards=[...step('Require the approved development server').matchAll(/node -e '([^']+)'/g)].slice(0,3).map(m=>m[1]);
  assert.equal(guards.length,3);
  for(let mask=0;mask<16;mask++){
    const env=Object.fromEntries(['API_ONLY','LOCAL_API_ONLY','DATABASE_SYNC_ONLY','BUSINESS_ONLY'].map((name,i)=>[name,String(Boolean(mask&(1<<i)))]));
    const run=()=>guards.forEach(body=>runInNewContext(body,{process:{env}}));
    if(Object.values(env).filter(v=>v==='true').length>1)assert.throws(run,/Choose one diagnostic scope/);
    else assert.doesNotThrow(run);
  }
  const runtimeGuard=[...step('Require the approved development server').matchAll(/node -e '([^']+)'/g)].find(match=>match[1].includes('Pass the exact published Runtime source SHA'))[1];
  for(const expected of ['', 'd'.repeat(39), 'D'.repeat(40)])assert.throws(()=>runInNewContext(runtimeGuard,{process:{env:{BUSINESS_ONLY:'true',EXPECTED_RUNTIME_SHA:expected}}}),/Runtime source SHA/);
  assert.doesNotThrow(()=>runInNewContext(runtimeGuard,{process:{env:{BUSINESS_ONLY:'true',EXPECTED_RUNTIME_SHA:'d'.repeat(40)}}}));
  assert.doesNotThrow(()=>runInNewContext(runtimeGuard,{process:{env:{BUSINESS_ONLY:'false',EXPECTED_RUNTIME_SHA:''}}}));
  assert.match(step('Sweep the exact CI binary'),/\$businessArgs \+= '-BusinessOnly'/);
  for(const value of ["$coverage.diagnostic_only = $true","$coverage.publication_reusable = $false","$coverage.full_acceptance = $false","$coverage.release_acceptance = $false","$coverage.base_complete = $false","$coverage.coverage_full = $false","'api-smoke'","'supplemental_suites'","'business-independent-login'","'business-upload-confirmed'","'business-download-converged'","'business-cross-device-recall'"])assert(sweep.includes(value),value);
  const modelStages=["-Name 'model-install'",'share_cpu_container(sys.argv[2]',"Confirm-CloudRegistration $mainCloudAccount $reg","if (-not $reg.Ok)","if (-not $super)","if ($regAddr -ne $Server)","-Name 'model-engine-cpu'","-Name \"model-engine-configure-$configuredEngine\"","-Name 'model-engine-restore-cpu'","-Name 'model-probe-m3' -ArgList @('--json', 'model', 'probe', '--text'"];
  for(let i=0;i<modelStages.length;i++){
    assert.equal(sweep.split(modelStages[i]).length,2,modelStages[i]);
    if(i)assert(sweep.indexOf(modelStages[i-1])<sweep.indexOf(modelStages[i]),modelStages[i]);
  }
  const engineCalls=sweep.split('\n').filter(line=>line.includes('Invoke-Om -Name')&&line.includes("'model', 'engine',"));
  assert.equal(engineCalls.length,3);
  for(const line of engineCalls){
    assert.match(line,/-DataDir \$DirA/);
    assert.doesNotMatch(line,/-HostProfile|--direct/);
  }
  assert.match(sweep,/Assert-Smoke 'model-engine-cpu-selected'[^\n]*\nif \(-not \$BusinessOnly\) \{\nforeach \(\$configuredEngine in @\('gpu', 'npu'\)\)/);
  assert.match(sweep,/Test-SmokeProfileRoot \(\[string\]\$st\.Envelope\.summary\.data_dir\) \$DirA/);
  assert.match(sweep,/Test-SmokeProfileRoot \$profileB \$DirB/);
  assert.match(sweep,/GetFullPath\(\$statusProfileB\) -ceq \[IO\.Path\]::GetFullPath\(\$profileB\)/);
  assert.match(sweep,/\[string\]\$_\.entry\.id -ceq \$id -and \[string\]\$_\.entry\.content -ceq/);
  const completion=sweep.split("Assert-Smoke 'business-cross-device-recall'")[1].split("Invoke-Om -Name 'show-b'")[0];
  assert(completion.indexOf('Invoke-CloudCleanup')<completion.indexOf("$script:BusinessStatus = 'passed'"));
  assert.match(completion,/CloudCleanup\.passed/);assert.match(completion,/remaining_users/);assert.match(completion,/Status -eq 'skip'/);
});
test('standalone identity precedes credentials and every dependent fixture is fail-closed',()=>{
  for(const text of ['ARTIFACT_SOURCE: build','VALIDATION_PROFILE: full','RSRS_RUNTIME_TRIPLE: ${{ matrix.target }}']) assert(workflow.includes(text));
  const ordered=['id: verified_artifact','id: supplement_python','id: standalone_runtime','id: native_credentials','name: Sweep the exact CI binary'];
  for(let i=1;i<ordered.length;i++)assert(workflow.indexOf(ordered[i-1])<workflow.indexOf(ordered[i]));
  assert.match(binding,/steps.verified_artifact.outcome == 'success'/);
  assert.match(binding,/steps.supplement_python.outcome == 'success'/);
  assert.match(binding,/RSRS_DATA_DIR: \$\{\{ runner.temp \}\}\/diagnostic-runtime-proof/);
  assert.match(binding,/node scripts\/ci-install-pinned-runtime.mjs "\$exe"/);
  for(const name of ['Sweep the exact CI binary','Verify all supplementary CLI contracts','Verify historical Secret Service profile migration','Verify native encrypted profile migration','Verify migrated legacy ciphertext on an independent current device','Diagnose runtime contracts without a full release claim']){
    const condition=step(name).split('\n')[0];
    assert(condition.includes("steps.standalone_runtime.outcome == 'success'"),name);
    assert(condition.includes("runner.os != 'Linux' || steps.native_credentials.outcome == 'success'"),name);
    const evaluate=(runtime,credentials,os='Linux')=>runInNewContext(condition.slice(condition.indexOf('${{')+3,condition.lastIndexOf('}}')),{cancelled:()=>false,inputs:{local_api_only:name.startsWith('Diagnose'),database_sync_only:name.startsWith('Verify migrated')},runner:{os},steps:{standalone_runtime:{outcome:runtime},native_credentials:{outcome:credentials},supplement_python:{outcome:'success'}}});
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
  const state={pin:{required:'2.0.0-dev.6',accept:'>=2.0.0-dev.6,<3.0.0'},metadata:{git_sha:'c'.repeat(40),version:'1.2.3-dev.4',producer:{run_id:42,run_attempt:2},target:'x86_64-unknown-linux-musl',binary_sha256:hash('CLI')},inventory:{command:'runtime.list',status:'ok',summary:{required:'2.0.0-dev.6',accept:'>=2.0.0-dev.6,<3.0.0'}},version:{command:'version',status:'ok',summary:{version:'1.2.3-dev.4'}},display:'rsrs 1.2.3-dev.4',cli:'CLI',runtime:'RUNTIME',runtimePath:'/temp/proof/bin/runtime/2.0.0-dev.6/rsrs-runtime'};
  state.runtimeMetadata={schema_version:2,runtime_version:state.pin.required,target_triple:state.metadata.target,binary_sha256:hash(state.runtime),source_commit:'d'.repeat(40)};
  state.receipt={version:state.pin.required,sha256:hash(state.runtime),release:{metadata_json:JSON.stringify(state.runtimeMetadata)}};
  state.receipt.release.metadata_sha256=hash(state.receipt.release.metadata_json);
  change(state);
  const env={RSRS_DATA_DIR:'/temp/proof',RUNNER_TEMP:'/temp',RSRS_RUNTIME_TRIPLE:state.metadata.target,CLI_SHA:'c'.repeat(40),CLI_RUN_ID:'42',GITHUB_SHA:'a'.repeat(40),GITHUB_RUN_ID:'43',GITHUB_RUN_ATTEMPT:'1',GH_TOKEN:'synthetic-secret',SERVICE_API_KEY:'synthetic-secret',RSRS_RUNTIME_BIN:'untrusted',BUSINESS_ONLY:String(Boolean(state.business)),EXPECTED_RUNTIME_SHA:state.expectedRuntime??''};
  let report;
  const fs={realpathSync:p=>p==='cli'?'/cli':state.runtimePath,readFileSync:p=>p==='runtime-pin.json'?JSON.stringify(state.pin):p.startsWith('validated-cli/')?JSON.stringify(state.metadata):p==='/temp/proof/bin/runtime.json'?JSON.stringify(state.receipt):p==='/cli'?state.cli:state.runtime,writeFileSync:(p,text)=>{assert.equal(p,'/temp/standalone-diagnostic-identity.json');report=JSON.parse(text);}};
  const cp={execFileSync:(binary,args,options)=>{assert.equal(binary,'/cli');assert.equal(options.timeout,30000);for(const key of ['GH_TOKEN','SERVICE_API_KEY','RSRS_RUNTIME_BIN'])assert.equal(options.env[key],undefined);assert.equal(options.env.HOME,'/temp/proof/home');return args.includes('list')?JSON.stringify(state.inventory):args.includes('v')?JSON.stringify(state.version):state.display;}};
  runInNewContext(script,{require:name=>({fs,path:path.posix,child_process:cp,'assert/strict':assert,crypto:{createHash}})[name],process:{argv:['node','-','cli'],env,platform:'linux'}});
  return report;
}
test('executed identity body separates H from C and records only verified installation proof',()=>{
  const report=simulate();assert.equal(report.harness_sha,'a'.repeat(40));assert.equal(report.cli_source_sha,'c'.repeat(40));assert.equal(report.producer.run_id,42);assert.equal(report.producer.run_attempt,2);
  assert.equal(report.cli.binary_sha256,hash('CLI'));assert.equal(report.runtime.binary_sha256,hash('RUNTIME'));
  assert.equal(report.diagnostic_only,true);assert.equal(report.full_acceptance,false);assert.equal(report.publication_reusable,false);
  assert(!JSON.stringify(report).includes('synthetic-secret'));
  const business=simulate(s=>{s.business=true;s.expectedRuntime='d'.repeat(40)});
  assert.equal(business.expected_runtime_source_sha,'d'.repeat(40));
});
test('executed identity body rejects mismatched pin, producer, C version, hashes and Runtime proof',()=>{
  for(const change of [s=>{s.business=true;s.expectedRuntime='f'.repeat(40)},s=>{s.business=true;s.expectedRuntime=''},s=>s.inventory.summary.required='2.0.0-dev.5',s=>s.inventory.summary.accept='*',s=>s.inventory.status='fail',s=>s.metadata.git_sha='a'.repeat(40),s=>s.metadata.producer.run_id=41,s=>s.cli+='changed',s=>s.version.summary.version='1.2.3-dev.5',s=>s.version.status='fail',s=>s.display+='wrong',s=>s.receipt.version='2.0.0-dev.5',s=>s.receipt.release.metadata_sha256='0'.repeat(64),s=>s.runtime+='changed',s=>s.runtimePath='/cli',s=>{s.runtimeMetadata.binary_sha256='0'.repeat(64);s.receipt.release.metadata_json=JSON.stringify(s.runtimeMetadata);s.receipt.release.metadata_sha256=hash(s.receipt.release.metadata_json);},s=>{s.runtimeMetadata.target_triple='wrong';s.receipt.release.metadata_json=JSON.stringify(s.runtimeMetadata);s.receipt.release.metadata_sha256=hash(s.receipt.release.metadata_json);},s=>{s.runtimeMetadata.runtime_version='wrong';s.receipt.release.metadata_json=JSON.stringify(s.runtimeMetadata);s.receipt.release.metadata_sha256=hash(s.receipt.release.metadata_json);}])assert.throws(()=>simulate(change));
});
test('all bash step bodies parse offline',()=>{
  for(const block of workflow.split(/\n      - (?:name|uses):/)){
    if(!block.includes('shell: bash')||!block.includes('        run: |\n'))continue;
    const body=block.split('        run: |\n')[1].replace(/^          /gm,'');
    const result=spawnSync('bash',['-n'],{input:body,encoding:'utf8',timeout:5000});assert.equal(result.status,0,result.stderr);
  }
});
