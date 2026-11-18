// Synthetic raw reports shared by existing offline release contract tests only.
import {mkdirSync,writeFileSync,readFileSync,copyFileSync} from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {publishedAssetNames} from './extract-artifact.mjs';
import {candidateHash} from './candidate-artifact.mjs';
const m=JSON.parse(readFileSync(new URL('../artifact-manifest.json',import.meta.url)));
export function publishedFullFixture(root,{candidate,assets,packsFolder}={}) {
  const targets=m.targets.map(t=>t.triple), manifestHash=candidate?candidateHash(candidate):'d'.repeat(64), context=candidate?{sha:candidate.source.sha,run_id:candidate.source.run_id,run_attempt:candidate.source.run_attempt}:{sha:'e'.repeat(40),run_id:901,run_attempt:2};
  const runtimeTargets=targets;
  let id=1;
  const spec={schema:2,...Object.fromEntries(['cli','runtime'].map(kind=>[kind,{repository:`risense-ai/respire-${kind}`,version:kind==='cli'?'1.0.21-dev.5':'1.0.21-dev.4',source_sha:(kind==='cli'?'a':'b').repeat(40),release_id:kind==='cli'?21:22,producer:{run_id:91,run_attempt:2},assets:(kind==='cli'?targets:runtimeTargets).flatMap(target=>publishedAssetNames(kind,target).map(name=>({id:id++,name,size:64,sha256:(kind==='cli'?'a':'b').repeat(64)})))}]))};
  if(candidate){
    spec.cli={repository:candidate.source.repository,source_sha:candidate.source.sha,version:candidate.source.version,
      producer:{run_id:candidate.source.run_id,run_attempt:candidate.source.run_attempt},assets:assets.map(({file,...entry})=>({name:file,...entry}))};
    spec.runtime=candidate.runtime;
  }
  const jobs=[];
  const job=name=>jobs.push({name,status:'completed',conclusion:'success',run_id:context.run_id,run_attempt:context.run_attempt,head_sha:context.sha});
  function put(artifact,file,value) {const location=path.join(root,artifact,file);mkdirSync(path.dirname(location),{recursive:true});writeFileSync(location,JSON.stringify(value));}
  const identity={source_sha:spec.cli.source_sha,version:spec.cli.version,binary_sha256:spec.cli.assets.find(a=>a.name===publishedAssetNames('cli',targets[0])[1]).sha256};
  const processReceipt={manifest_sha256:manifestHash,bundle_sha256:'b'.repeat(64),image_sha256:'b'.repeat(64),exe:'/isolated/runtime',pid:42,process_start_id:'synthetic-birth',installation_root:'/isolated',data_dir:'/isolated/profile',account_id:'account',instance_id:'instance',generation:1,protocol_v:1};
  const runtime={...identity,passed:true,runtime_mode:'standalone_runtime',standalone_runtime_evidence:true,runtime_binary_sha256:'b'.repeat(64),runtime_version:spec.runtime.version,runtime_identity_receipts:[processReceipt]};
  const upgradedRuntime={...runtime,upgrade_contract:'standalone-v1',runtime_installed_after_legacy_data:true,legacy_handoff_actor:null};
  const policy=JSON.parse(execFileSync(process.platform==='win32'?'py':'python3',
    [...(process.platform==='win32'?['-3']:[]),'-I','-B','-c',`import json,sys
sys.path.insert(0, '.')
from published_upgrade_policy import DATABASE_DEV_CHECKPOINTS, platform_applicability
gaps = {}
for target in json.load(sys.stdin):
    gaps[target] = {}
    for tag in ['v1.0.19', 'v1.0.20', *DATABASE_DEV_CHECKPOINTS]:
        try:
            gaps[target][tag] = platform_applicability(tag, target, [])
        except ValueError:
            pass
print(json.dumps({'checkpoints': DATABASE_DEV_CHECKPOINTS, 'gaps': gaps}))`],
    {cwd:new URL('../../scripts/',import.meta.url),input:JSON.stringify(targets),encoding:'utf8',windowsHide:true}));
  const upgradeReports={};
  for(const target of targets) {
    job(`validate / Release (${target})`);job(`native-regression / Native (${target})`);
    const runtime_producer={...spec.runtime.producer,source_sha:spec.runtime.source_sha,target,metadata_sha256:'b'.repeat(64),
      binary_sha256:'b'.repeat(64),archive_sha256:'b'.repeat(64),artifacts:['runtime-release-','runtime-smoke-'].map((prefix,i)=>({id:31+i,job_id:11+i,name:prefix+target,zip_sha256:'c'.repeat(64)}))};
    put('published-assets-verification-'+target,'published-assets-receipt.json',{assets_verified:true,payloads_verified:true,target,manifest_sha256:manifestHash,harness_sha:context.sha,run_id:String(context.run_id),run_attempt:String(context.run_attempt),product_sources:{cli:spec.cli.source_sha,runtime:spec.runtime.source_sha},releases:Object.fromEntries(['cli','runtime'].map(kind=>[kind,{...spec[kind],assets:undefined}])),runtime_producer,assets:['cli','runtime'].flatMap(kind=>spec[kind].assets.filter(a=>a.name.includes(target)).map(a=>({repository:spec[kind].repository,...a})))});
    if(candidate)put('candidate-assets-'+target,'candidate-assets-receipt.json',{schema:1,kind:'candidate-assets-verification',candidate,target,manifest_sha256:manifestHash,
      assets_verified:true,payloads_verified:true,cli_assets:publishedAssetNames('cli',target).map(name=>spec.cli.assets.find(a=>a.name===name)),runtime_producer,
      payload_identity:{cli_binary_sha256:identity.binary_sha256,runtime_core:{sdk_manifest_expected_sha256:'c'.repeat(64),sdk_archive_expected_sha256:'c'.repeat(64)}}});
    put('resident-concurrency-'+target,'real-account-return-verification.json',[runtime]);
    put('resident-concurrency-'+target,'resident-stress-metrics.json',{passed:true});
    put('resident-concurrency-'+target,'fixture-dependencies.json',{synthetic:true});
    put('resident-concurrency-'+target,'fixture-process-verification.json',[{passed:true}]);
    const formal=['v1.0.19','v1.0.20'], selected=[...formal,...Object.keys(policy.checkpoints)].sort();
    upgradeReports[target]={passed:true,profile:'full',full_coverage:true,all_published_sources_covered:true,
      upgrade_contract:'standalone-v1',target,candidate_sha256:identity.binary_sha256,published_formal_sources:formal,
      additional_draft_baselines:[],database_dev_checkpoints:policy.checkpoints,selected_sources:selected,
      first_platform_release:false,sources:selected.map(tag=>({version:tag.slice(1),formal:formal.includes(tag),
        ...(policy.gaps[target][tag]?{status:'not-applicable',reason:policy.gaps[target][tag]}:{passed:true,upgrade_contract:'standalone-v1'})}))};
    put('published-upgrades-'+target,'published-upgrades.json',upgradeReports[target]);
    for(const row of upgradeReports[target].sources.filter(row=>row.passed))put('published-upgrades-'+target,'v'+row.version+'/results/real-account-return-verification.json',[upgradedRuntime]);
    if(target==='x86_64-unknown-linux-gnu')continue;
    job(`cloud-sweep (runner, ${target})`);
    put('base-release-sweep-'+target,'coverage.json',{...identity,observed_version:spec.cli.version,expected_version:spec.cli.version,base_complete:true,failed:0,required_missing:[]});
    if(target.includes('linux')) {
      put('release-sweep-'+target,'combined-coverage.json',{...identity,schema:2,scope:'database-in-place-upgrade',profile_import:{required:false,status:'not-run'},complete:true});
      put('release-sweep-'+target,'suite-results.json',['outbox','ai_inject','runtime','legacy_vault','login_interruption'].map(suite=>({suite,passed:true,exit:0})));
      for(const name of ['ai-inject-coverage.json','legacy-vault-coverage.json','interruption-coverage.json'])put('release-sweep-'+target,name,{...identity,passed:true});
      for(const name of ['outbox-coverage.json','runtime-coverage.json'])put('release-sweep-'+target,name,runtime);
      put('secret-service-profile-migration-'+target,'interruption-coverage.json',{...identity,passed:true});
    }
  }
  put('gnu-login-interruption','interruption-coverage.json',{...identity,passed:true});
  job('validate / npm-dry-run');job('api-smoke');
  const packageManifest=JSON.parse(readFileSync(new URL('../artifact-manifest.json',import.meta.url)));
  const packages=packsFolder?JSON.parse(readFileSync(path.join(packsFolder,'source-version.json'))).packages:[...packageManifest.targets.map(t=>t.pkg),packageManifest.npmScope].map((name,i)=>{
    const file=`synthetic-${i}.tgz`,bytes=Buffer.from(`synthetic package ${i}`);
    mkdirSync(path.join(root,'npm-release-packages'),{recursive:true});writeFileSync(path.join(root,'npm-release-packages',file),bytes);
    return {name,version:spec.cli.version,file,sha256:createHash('sha256').update(bytes).digest('hex')};
  });
  put('npm-release-packages','published-package-validation.json',{artifact_source:'published-assets',harness_sha:context.sha,manifest_sha256:manifestHash,product_sources:{cli:spec.cli.source_sha,runtime:spec.runtime.source_sha},run_id:context.run_id,run_attempt:context.run_attempt,packages});

  if(candidate){
    for(const p of packages)copyFileSync(path.join(packsFolder,p.file),path.join(root,'npm-release-packages',p.file));
    put('npm-release-packages','source-version.json',{schema_version:1,git_sha:spec.cli.source_sha,version:spec.cli.version,packages,
      producer:{repository:spec.cli.repository,run_id:String(context.run_id),run_attempt:context.run_attempt,sha:context.sha,job:'npm-dry-run'}});
  }
  const offline={status:'native-connectivity-passed',identity_verified:true,offline:{status:'offline-subset-passed',recall_hit:true,runtime_normal_stop_confirmed:true,automatic_start:true,automatic_key_handoff:true}};
  put('client2-published-online-x86_64-pc-windows-msvc','report.json',{status:'connectivity-passed',environment_ready:true,cleanup_exit_confirmed:true,
    cli_sha256:identity.binary_sha256,runtime_archive_sha256:'b'.repeat(64),official_exe_verified:true,exe_sha256:'f'.repeat(64),source_sha:'f'.repeat(40),release:candidate?.client2.release||'v2.0.0-dev.6',
    native_window_visible:true,isolated_webview_bound:true,native_accessibility_read:true,foreground_verified:true,gui_input_observed:true,target_desktop_screenshot_saved:true,
    restart:{completed:true,original_tree_absent:true},recovery:{status:'recovery-subset-passed',original_operation_not_repeated:true,saved_restart:{saved_restart_no_prompt:true}},
    initial_native_gui:offline,restart_native_gui:offline,cli_processes:['initial','restart'].map(phase=>({phase,pid:42,parent_pid:40,started_ticks:'12345',sha256:identity.binary_sha256,parent_verified:true,session_verified:true,lifetime_verified:true})),
    [candidate?'candidate_inputs':'published_inputs']:{manifest_sha256:manifestHash,cli_source:spec.cli.source_sha,runtime_source:spec.runtime.source_sha}});
  const apiReports={};
  for(const name of ['dev-api-coverage.json','dev-github-api-coverage.json']) {
    put('dev-api-coverage',name,{complete:true,...(name==='dev-api-coverage.json'?{cli_workflow_sha:context.sha}:{} )});
    apiReports[name]=createHash('sha256').update(readFileSync(path.join(root,'dev-api-coverage',name))).digest('hex');
  }
  put('dev-api-coverage','published-api-identity.json',{harness_sha:context.sha,manifest_sha256:manifestHash,run_id:context.run_id,run_attempt:context.run_attempt,reports:apiReports});
  return {spec,targets,manifestHash,context,jobs,put,runtime,upgradedRuntime,upgradeReports};
}
