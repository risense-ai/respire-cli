import test from 'node:test';
import assert from 'node:assert/strict';
import {runInNewContext} from 'node:vm';
import {readFileSync,mkdtempSync,mkdirSync,writeFileSync,existsSync,rmSync,readdirSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {spawnSync,execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {regressionContract,validateRegressionContract,validationProfile,regressionStatus,regressionCompletedAt} from './release-regression-contract.mjs';
import {requireRegressions} from './cleanup-release-artifacts.mjs';
import {frontendLayout,releaseAssetNames,verifyBinary} from './verify-binary.mjs';
import {publishedAssetNames,parsePublishedAssets,validateArtifactRequest} from './extract-artifact.mjs';
import {createHash} from 'node:crypto';
const manifest=JSON.parse(readFileSync(new URL('../artifact-manifest.json',import.meta.url)));
const contract=regressionContract(manifest),copy=structuredClone;
test('API smoke shell parses even when published-assets mode is inactive',()=>{
  const workflow=readFileSync(new URL('../../.github/workflows/release.yml',import.meta.url),'utf8');
  const job=workflow.split('\n  api-smoke:\n')[1].split('\n  publish:\n')[0];
  const script=job.split('        run: |\n')[1].split('\n      - uses:')[0].replace(/^          /gm,'');
  const result=spawnSync('bash',['-n'],{input:script,encoding:'utf8'});
  assert.equal(result.status,0,result.stderr);
  assert.match(script,/dev-api-smoke.py/);assert.match(script,/dev-github-api-smoke.py/);
});
const job=name=>({name,status:'completed',conclusion:'success'});
const inventory=()=>[...contract.native.map(t=>job(`native-regression / Native (${t})`)),...contract.cloud.map(t=>job(`cloud-sweep (runner, ${t})`)),...contract.migration.map(t=>job(`Native migration (${t})`)),...contract.migration_gate.map(t=>job(`Migration gate (${t})`)),job('api-smoke'),job('publish')];
test('frontend artifacts extract, verify and pack exact CLI bytes without a fabricated SDK inventory',()=>{
  const root=mkdtempSync(path.join(tmpdir(),'cli-frontend-pack-'));
  const workspace=fileURLToPath(new URL('../../',import.meta.url));
  const script=name=>fileURLToPath(new URL(name,import.meta.url));
  const sha=execFileSync('git',['rev-parse','HEAD'],{cwd:workspace,encoding:'utf8'}).trim();
  const gitDir=execFileSync('git',['rev-parse','--absolute-git-dir'],{cwd:workspace,encoding:'utf8'}).trim();
  const env={...process.env,GIT_DIR:gitDir};
  const run=(name,args=[],extra={})=>spawnSync(process.execPath,[script(name),...args],{cwd:root,env:{...env,...extra},encoding:'utf8',timeout:30000});
  try{
    assert.equal(frontendLayout(manifest),true);
    assert.throws(()=>frontendLayout({...manifest,artifactLayout:'unknown'}));
    for(const folder of ['assets','bins','cli','npm/bin'])mkdirSync(path.join(root,folder),{recursive:true});
    writeFileSync(path.join(root,'cli/Cargo.toml'),`version = "${manifest.cliVersion}"\n`);
    writeFileSync(path.join(root,'npm/artifact-manifest.json'),JSON.stringify(manifest));
    for(const file of ['LICENSE','COMMERCIAL-LICENSE.md','npm/README.md','npm/bin/cli.js'])writeFileSync(path.join(root,file),readFileSync(path.join(workspace,file)));
    for(const target of manifest.targets){
      const bytes=Buffer.alloc(128),arm=target.triple.startsWith('aarch64');
      if(target.triple.includes('windows')){
        bytes.write('MZ');bytes.writeUInt32LE(64,0x3c);bytes.write('PE\0\0',64);
        bytes.writeUInt16LE(arm?0xaa64:0x8664,68);bytes.writeUInt16LE(0x20b,88);
      }else if(target.triple.includes('darwin')){
        bytes.writeUInt32LE(0xfeedfacf,0);bytes.writeUInt32LE(arm?0x100000c:0x1000007,4);
      }else{
        bytes.set([0x7f,0x45,0x4c,0x46,2,1]);bytes.writeUInt16LE(arm?183:62,18);
      }
      const [binary,metadata]=releaseAssetNames(manifest,target.triple);
      assert.equal(releaseAssetNames(manifest,target.triple).length,2);
      writeFileSync(path.join(root,'assets',binary),bytes);
      writeFileSync(path.join(root,'assets',metadata),JSON.stringify({schema_version:2,artifact_layout:manifest.artifactLayout,
        git_sha:sha,version:manifest.cliVersion,target:target.triple,binary_file:binary,binary_size:bytes.length,
        binary_sha256:createHash('sha256').update(bytes).digest('hex'),producer:{run_id:'700',run_attempt:1}}));
      const result=run('extract-artifact.mjs',['assets',path.join('bins',target.triple,'release')],
        {CLI_TARGET:target.triple,CLI_SHA:sha,CLI_VERSION:manifest.cliVersion});
      assert.equal(result.status,0,result.stderr);
    }
    const verified=run('verify-packages.mjs',['assets','--assets-only']);assert.equal(verified.status,0,verified.stderr);
    const packed=run('pack.mjs',['--repo',root,'--root',path.join(root,'bins')]);assert.equal(packed.status,0,packed.stderr);
    for(const target of manifest.targets){
      const files=readdirSync(path.join(root,'npm/dist',target.pkg,'bin'));
      assert.deepEqual(files,[manifest.binaryName+(target.triple.includes('windows')?'.exe':'')]);
    }
    const runtime=path.join(root,'assets',`rsrs-${manifest.targets[0].triple}-runtime.tar.gz`);
    writeFileSync(runtime,'stale SDK archive');assert.notEqual(run('verify-packages.mjs',['assets','--assets-only']).status,0);
    rmSync(runtime);
    writeFileSync(path.join(root,'bins',manifest.targets[0].triple,'release/core-runtime.json'),'{}');
    assert.notEqual(run('pack.mjs',['--repo',root,'--root',path.join(root,'bins')]).status,0);
    const workflow=readFileSync(new URL('../../.github/workflows/release-validation.yml',import.meta.url),'utf8');
    const container=readFileSync(new URL('../../scripts/build-linux-musl-container.sh',import.meta.url),'utf8');
    assert.doesNotMatch(workflow,/sdk-ci-cache|fetch-core-sdk|stage-core-runtime|check-sdk-release/);
    assert.doesNotMatch(container,/RSRS_CORE_SDK_DIR|fetch-core-sdk|stage-core-runtime/);
    assert.match(workflow,/Verify real macOS CPU inference/);assert.match(workflow,/require-native-linux-arm64/);
  }finally{rmSync(root,{recursive:true,force:true});}
});
test('published Darwin ARM64 alias requires the exact 64-bit Mach-O CPU header',()=>{
  const alias='aarch64-apple-darwin',entry=manifest.targets.find(t=>t.triple===alias);
  assert.deepEqual(entry.os,['darwin']);assert.deepEqual(entry.cpu,['arm64']);
  const root=mkdtempSync(path.join(tmpdir(),'verify-binary-alias-')),file=path.join(root,'image');
  const macho=(magic,cpu)=>{const bytes=Buffer.alloc(64);bytes.writeUInt32LE(magic,0);bytes.writeUInt32LE(cpu,4);return bytes};
  const elf=Buffer.alloc(64);elf.set([0x7f,0x45,0x4c,0x46,2,1]);elf.writeUInt16LE(183,18);
  const pe=Buffer.alloc(128);pe.write('MZ');pe.writeUInt32LE(64,0x3c);pe.write('PE\0\0',64);pe.writeUInt16LE(0xaa64,68);pe.writeUInt16LE(0x20b,88);
  try{
    for(const target of [alias,['aarch64','apple','darwin'].join('-')]){
      writeFileSync(file,macho(0xfeedfacf,0x100000c));assert.doesNotThrow(()=>verifyBinary(file,target));
    }
    for(const [label,bytes,target] of [
      ['x64 CPU',macho(0xfeedfacf,0x1000007),alias],
      ['ARM32 CPU',macho(0xfeedfacf,12),alias],
      ['32-bit Mach-O',macho(0xfeedface,0x100000c),alias],
      ['fat Mach-O',macho(0xcafebabe,0x100000c),alias],
      ['wrong endian',macho(0xcffaedfe,0x100000c),alias],
      ['ELF',elf,alias],['PE',pe,alias],
      ['near alias',macho(0xfeedfacf,0x100000c),alias+'-other'],
      ['unknown target',macho(0xfeedfacf,0x100000c),'foreign-target'],
      ['x64 target',macho(0xfeedfacf,0x100000c),'x86_64-apple-darwin'],
    ]){
      writeFileSync(file,bytes);assert.throws(()=>verifyBinary(file,target),/Unsupported binary target|Binary header does not match/,label);
    }
  }finally{rmSync(root,{recursive:true,force:true})}
});
test('supported Linux ARM targets require native runners, every source feedback phase and background install proof',async()=>{
  const text=file=>readFileSync(new URL('../../.github/workflows/'+file,import.meta.url),'utf8');
  for(const file of ['ci.yml','release-validation.yml','release-native-validation.yml','release.yml']){
    const workflow=text(file).replace(/\r\n/g,'\n');
    for(const {triple} of manifest.targets.filter(t=>t.triple.startsWith('aarch64-unknown-linux-')))assert(workflow.includes('os: ubuntu-24.04-arm\n            target: '+triple),file+' missing native ARM target '+triple);
    assert(workflow.includes('scripts/require-native-linux-arm64.sh'),file+' lacks hardware check');
  }
  const source=text('token-free-sdk-check.yml');assert.match(source,/if: \$\{\{ !contains\(inputs.target, '-musl'\) \}\}/);
  assert.match(source,/run: bash scripts\/build-linux-musl.sh \$\{\{ inputs.target \}\}/);
  assert.match(source,/if: \$\{\{ inputs.feedback_probe && inputs.target != 'x86_64-apple-darwin' && contains\(inputs.target, '-musl'\) \}\}/);
  assert.match(source,/scripts\/verify-linux-arm64-elf.sh/);assert.match(source,/diary_tests/);assert.match(source,/feedback_contract_probe/);
  assert.match(source,/scripts\/probe-native-arm64-alpine.sh/);
  for(const file of ['ci.yml','release-native-validation.yml'])assert.match(text(file),/scripts\/probe-native-arm64-alpine.sh/);
  const alpine=readFileSync(new URL('../../scripts/probe-native-arm64-alpine.sh',import.meta.url),'utf8');
  assert.match(alpine,/--network none/);assert.match(alpine,/--direct model probe --json/);
  assert.match(alpine,/RSRS_CPU_OWNED_ORT_FILE=\/cpu-model\.ort/);assert.equal((alpine.match(/sha256sum -c >\/dev\/null/g)||[]).length,4);
  assert.doesNotMatch(alpine,/--check|--status/);
  assert.match(alpine,/--json runtime start/);assert.match(alpine,/--json runtime stop/);assert.match(alpine,/trap .* EXIT/);
  assert(alpine.indexOf('test -r /cpu-model.ort')<alpine.indexOf('--direct model probe'),'mounted CPU artifact must be checked before inference');
  assert.match(alpine,/test -z "\$\{RSRS_CORE_TEST_MODE:-\}"/);assert.doesNotMatch(alpine,/-e (?:GH_TOKEN|GITHUB_TOKEN|CORE_SDK_READ_TOKEN|RSRS_CORE_TEST_MODE)/);
  const background=text('verify-publication.yml').split('  verify-publication-arm64:')[1];
  assert.match(background,/runs-on: ubuntu-24.04-arm/);assert.match(background,/VERIFY_ARM64: 'true'/);
  assert.match(background,/publication-arm64-verified-/);assert.doesNotMatch(background,/id-token:|contents: write|actions: write|npm publish|concurrency:/);
  const native=text('release-native-validation.yml').replace(/\r\n/g,'\n');
  const step=name=>native.split('      - name: '+name+'\n')[1]?.split('\n      - ')[0];
  const install=step('Install and verify the official pinned standalone Runtime');
  assert.match(install,/id: pinned-runtime/);assert.match(install,/if: inputs.artifact_source != 'published-assets'/);
  const dataRoot=block=>block.match(/^          RSRS_DATA_DIR: (.+)$/m)?.[1];
  assert.equal(dataRoot(install),'${{ runner.temp }}/release-probe');
  assert.equal(dataRoot(install),dataRoot(step('Install and probe BGE CPU inference')));
  assert(native.indexOf('id: pinned-runtime')<native.indexOf('      - name: Install and probe BGE CPU inference'));
  const script=install.split("<<'NODE'\n")[1].split('\n          NODE')[0].replace(/^          /gm,'').replace(/^import .*;\n/gm,'')
    .replace("const {installPinnedRuntime} = await import('./scripts/ci-install-pinned-runtime.mjs');",'');
  for(const platform of ['linux','win32']) {
    const p=platform==='win32'?path.win32:path.posix, root=platform==='win32'?'C:\\runner\\native-runtime':'/runner/native-runtime';
    const image=Buffer.from('synthetic installed Runtime; never executed'), version='1.0.21-dev.5';
    const digest=createHash('sha256').update(image).digest('hex'), metadata=JSON.stringify({triple:'synthetic-target',runtime_version:version});
    const simulate=async change=>{
      const selected={version,sha256:digest,release:{metadata_json:metadata,metadata_sha256:createHash('sha256').update(metadata).digest('hex')}};
      const state={selected,status:0,sameImage:false,hosted:'true'};change?.(state);
      const tokenSentinel='fixture-only-value';
      const output=[],calls=[],env={GITHUB_ACTIONS:'true',RUNTIME_FIXTURE_HOSTED:state.hosted,CLI_TARGET:'synthetic-target',RUNNER_TEMP:p.dirname(root),RSRS_DATA_DIR:root,GITHUB_OUTPUT:'fixture-output',GH_TOKEN:tokenSentinel,GITHUB_TOKEN:tokenSentinel};
      await runInNewContext(`(async()=>{${script}\n})()`,{assert,createHash,join:p.join,resolve:(...parts)=>p.resolve(...parts),process:{platform,env},
        mkdirSync:()=>{},statSync:()=>({isFile:()=>true}),
        realpathSync:file=>state.sameImage?'same-image':file,
        readFileSync:file=>file==='runtime-pin.json'?JSON.stringify({required:version}):file===p.join(root,'bin','runtime.json')?JSON.stringify(selected):image,
        appendFileSync:(_file,line)=>output.push(line),
        installPinnedRuntime:async(cli,options,target)=>{assert.equal(target,'synthetic-target');
          calls.push({cli,env:options.env});return {status:state.status}}});
      assert.equal(calls.length,1);assert.equal(calls[0].cli,p.resolve('target/ci','synthetic-target','release','rsrs'+(platform==='win32'?'.exe':'')));
      for(const token of ['GH_TOKEN','GITHUB_TOKEN']){assert.equal(calls[0].env[token],undefined);assert.equal(env[token],tokenSentinel);}
      assert.equal(calls[0].env.RSRS_DATA_DIR,root);assert.equal(calls[0].env.HOME,p.join(root,'home'));
      assert.equal(calls[0].env.RSRS_RUNTIME_TRIPLE,'synthetic-target');
      assert.deepEqual(output,[`path=${p.join(root,'bin','runtime',version,'rsrs-runtime'+(platform==='win32'?'.exe':''))}\n`,`sha256=${digest}\n`,`version=${version}\n`]);
    };
    await simulate();
    for(const change of [s=>s.status=1,s=>s.selected.version='1.0.21-dev.4',s=>s.selected.sha256='a'.repeat(64),
      s=>s.selected.release=null,s=>s.selected.release.metadata_sha256='b'.repeat(64),s=>s.sameImage=true,s=>s.hosted='false',
      s=>{s.selected.release.metadata_json=JSON.stringify({triple:'wrong-gnu-target',runtime_version:version});s.selected.release.metadata_sha256=createHash('sha256').update(s.selected.release.metadata_json).digest('hex');}])await assert.rejects(()=>simulate(change));
  }
  for(const name of ['Verify the latest formal release upgrades automatically','Verify resident foreground and background inference under concurrent CLI load']) {
    const consumer=step(name);
    for(const [key,output,published] of [['BIN','path','RSRS_RUNTIME_BIN'],['SHA256','sha256','RSRS_PUBLISHED_RUNTIME_SHA256'],['VERSION','version','RSRS_PUBLISHED_RUNTIME_VERSION']])assert(consumer.includes(`NATIVE_RUNTIME_${key}: \u0024{{ inputs.artifact_source == 'published-assets' && env.${published} || steps.pinned-runtime.outputs.${output} }}`));
    assert.match(consumer,/test -n "\$NATIVE_RUNTIME_BIN" && test -n "\$NATIVE_RUNTIME_SHA256" && test -n "\$NATIVE_RUNTIME_VERSION"/);
    assert.match(consumer,/--runtime-binary "\$NATIVE_RUNTIME_BIN" --runtime-sha256 "\$NATIVE_RUNTIME_SHA256" --runtime-version "\$NATIVE_RUNTIME_VERSION"/);
  }
  assert.match(step('Verify the latest formal release upgrades automatically'),/GH_TOKEN: \$\{\{ github.token \}\}/);
  assert.doesNotMatch(native,/RSRS_ARTIFACT_SOURCE: published-assets|RSRS_PUBLISHED_ASSETS_SHA256:|RSRS_PUBLISHED_BUNDLE_SHA256:/);
  const account=readFileSync(new URL('../../scripts/test-real-m3-account-switch.py',import.meta.url),'utf8');
  assert.match(account,/if key not in \('GH_TOKEN', 'GITHUB_TOKEN'\)/);
  assert.match(account,/web_help=subprocess\.check_output\(\[args.seed_binary,'web','--help'\],env=seed_env,/);
  const probe=step('Install and probe BGE CPU inference');
  assert.match(probe,/NATIVE_RUNTIME_BIN: \$\{\{ inputs.artifact_source == 'published-assets' && env.RSRS_RUNTIME_BIN \|\| steps.pinned-runtime.outputs.path \}\}/);
  assert.match(probe,/RSRS_RUNTIME_TRIPLE: \$\{\{ matrix.target \}\}/);
  assert.match(probe,/unset GH_TOKEN GITHUB_TOKEN/);
  assert.match(probe,/test -n "\$NATIVE_RUNTIME_BIN" && test -n "\$NATIVE_RUNTIME_SHA256" && test -n "\$NATIVE_RUNTIME_VERSION"/);
  assert.match(probe,/native_fixture_process.py --install-published "\$exe"/);
  assert.match(probe,/probe-native-arm64-alpine.sh[^\n]+"\$RSRS_RUNTIME_BIN" "\$NATIVE_RUNTIME_SHA256" "\$NATIVE_RUNTIME_VERSION"/);
  assert.match(alpine,/-v "\$bundle:\/runtime:ro"/);assert.match(alpine,/-v "\$receipt:\/runtime-selection\.json:ro"/);assert.doesNotMatch(alpine,/-e RSRS_RUNTIME_BIN=/);
  assert.match(alpine,/-e RSRS_RUNTIME_TRIPLE=aarch64-unknown-linux-musl/);
  assert.match(alpine,/\$NATIVE_RUNTIME_SHA256  \/runtime\/rsrs-runtime/);
  assert.match(alpine,/case "\$\(\/runtime\/rsrs-runtime --version\)"/);
});
test('new full gate requires every native, cloud, migration fixture, join and API success',()=>{
  validateRegressionContract(contract,manifest);assert.equal(contract.native.length,manifest.targets.length);assert.equal(contract.cloud.length,manifest.targets.length-1);assert.equal(contract.migration.length,3);assert.equal(contract.migration_gate.length,3);
  assert.equal(regressionStatus(inventory(),contract),'success');requireRegressions(inventory(),contract.native,contract);
  for(let index=0;index<inventory().length-1;index++){
    for(const conclusion of ['failure','cancelled','skipped',null]){
      const jobs=inventory();jobs[index].conclusion=conclusion;assert.throws(()=>regressionStatus(jobs,contract));assert.throws(()=>requireRegressions(jobs,contract.native,contract));
    }
    const absent=inventory();absent.splice(index,1);assert.equal(regressionStatus(absent,contract),'pending');assert.throws(()=>requireRegressions(absent,contract.native,contract));
    const pending=inventory();pending[index].status='in_progress';pending[index].conclusion=null;assert.equal(regressionStatus(pending,contract),'pending');
  }
});
test('duplicates, unknown targets and changed declared inventory cannot silently weaken the release/cleanup gate',()=>{
  for(const index of [0,4,7,9,11]){const jobs=inventory();jobs.push(copy(jobs[index]));assert.throws(()=>regressionStatus(jobs,contract));}
  const foreign=inventory();foreign[0].name='native-regression / Native (foreign-target)';assert.throws(()=>regressionStatus(foreign,contract));
  for(const key of ['native','cloud','migration','migration_gate']){const c=copy(contract);c[key].pop();assert.throws(()=>validateRegressionContract(c,manifest));}
});
test('workflow runs independent fixture work before the join, and keeps Linux supplement model dependencies serial',()=>{
  const workflow=readFileSync(new URL('../../.github/workflows/release.yml',import.meta.url),'utf8').replace(/\r\n/g,'\n');
  const part=name=>workflow.split(`\n  ${name}:\n`)[1]?.split(/\n  [a-z][\w-]*:\n/)[0];
  const migration=part('native-migration'),join=part('migration-gate'),base=part('cloud-sweep'),publish=part('publish'),ready=part('publication-ready');
  assert.match(migration,/needs: \[plan, artifact-inputs, published-assets-verification\]/);assert.doesNotMatch(migration,/needs:.*cloud-sweep|dev-smoke-gate.py|continue-on-error/);
  assert.match(migration,/dev-profile-migration-smoke.py/);assert.match(migration,/extract-artifact.mjs/);assert.match(migration,/verified-build.json/);
  assert.match(join,/\$schema = if \(\$manifest.artifactLayout -ceq 'cli-frontend-v2'\) \{ 2 \} else \{ 1 \}/);
  assert.match(join,/\$build.schema_version -ne \$schema -or \$build.artifact_layout -cne \$manifest.artifactLayout/);
  assert.match(join,/throw 'Unknown CLI artifact layout'/);
  assert.match(join,/needs: \[plan, cloud-sweep, native-migration, artifact-inputs, published-assets-verification\]/);assert.match(join,/base-release-sweep-/);assert.match(join,/native-profile-migration-fixture-/);
  assert.match(join,/--migration-only/);assert.match(join,/--binary-sha256 \$build.binary_sha256/);assert.match(join,/\$build.git_sha -ne \$env:CLI_SHA/);assert.match(join,/\$build.target -ne \$env:CLI_TARGET/);
  assert.doesNotMatch(base,/dev-profile-migration-smoke.py/);assert.match(base,/dev-smoke-supplements.py/);assert(base.indexOf('dev-smoke-supplements.py')<base.indexOf('dev-login-interruption-smoke.py'));
  assert.match(ready,/regressionStatus\(jobs,contract\)==='success'/);assert.doesNotMatch(ready,/native.length===4&&cloud.length===3/);assert.doesNotMatch(ready,/concurrency:|id-token:|contents: write/);assert.match(publish,/needs.publication-ready.result == 'success'/);assert.doesNotMatch(publish,/async function requireCi|async function requireRegression/);
});


test('full-validation clock includes required regressions that finish after fast-manual readiness',()=>{
  const jobs=inventory().map(j=>({...j,completed_at:'2026-10-27T00:03:00Z'}));
  jobs[0].completed_at='2026-10-27T00:08:00Z';
  jobs.find(j=>j.name==='publish').completed_at='2030-01-01T00:00:00Z';
  assert.equal(regressionCompletedAt(jobs,contract,'2026-10-27T00:05:00Z'),Date.parse('2026-10-27T00:08:00Z'));
  assert.equal(regressionCompletedAt(jobs,contract,'2026-10-27T00:09:00Z'),Date.parse('2026-10-27T00:09:00Z'));
});
test('missing, malformed, impossible or reversed required clocks never produce a full-validation duration',()=>{
  const jobs=inventory().map(j=>({...j,completed_at:'2026-10-27T00:03:00Z'}));
  for(const value of [undefined,null,'not-a-time','2026-02-31T00:00:00Z','2026-10-27T00:03:00']){
    const changed=copy(jobs);changed[0].completed_at=value;assert.equal(regressionCompletedAt(changed,contract,'2026-10-27T00:05:00Z'),null);
  }
  const reversed=copy(jobs);reversed[0].started_at='2026-10-27T00:04:00Z';assert.equal(regressionCompletedAt(reversed,contract,'2026-10-27T00:05:00Z'),null);
  assert.equal(regressionCompletedAt(jobs,contract,'not-a-time'),null);
});

// Plumbing simulation only: actual native inference remains a required hosted gate.
test('Alpine preflight mounts the selected CPU cache read-only and refuses missing/corrupt inputs before docker',()=>{
  const root=mkdtempSync(path.join(tmpdir(),'arm-alpine-paths-'));
  try{
    const bin=path.join(root,'bin'),models=path.join(root,'models with spaces'),data=path.join(root,'host profile'),capture=path.join(root,'docker.json');
    mkdirSync(bin);mkdirSync(path.join(models,'onnx'),{recursive:true});mkdirSync(path.join(data,'models/bge-m3/onnx'),{recursive:true});
    const exe=path.join(root,'rsrs'),cached=path.join(data,'models/bge-m3/onnx/model_quantized.cpu-v1.ort'),local=path.join(models,'onnx/model_quantized.cpu-v1.ort'),custom=path.join(root,'explicit cpu.ort');
    const installed=path.join(root,'complete musl runtime'),bundle=path.join(installed,'runtime','1.0.21-dev.5'),runtime=path.join(bundle,'rsrs-runtime'),receipt=path.join(installed,'runtime.json');mkdirSync(bundle,{recursive:true});
    writeFileSync(runtime,'fixture');writeFileSync(path.join(bundle,'core-runtime.json'),'fixture');writeFileSync(receipt,'fixture');
    for(const file of [exe,cached,custom,path.join(models,'tokenizer.json'),path.join(models,'onnx/model_quantized.onnx')])writeFileSync(file,'fixture');
    const stub=(name,body)=>writeFileSync(path.join(bin,name),body,{mode:0o755});
    stub('uname','#!/bin/sh\ncase "$1" in -s) echo Linux;; -m) echo aarch64;; esac\n');
    // The fake digest checker isolates selection/argv tests from the 570MB real model.
    stub('sha256sum','#!/bin/sh\ncat >/dev/null\nexit "${FAKE_HASH_STATUS:-0}"\n');
    stub('docker','#!'+process.execPath+'\nrequire("node:fs").writeFileSync(process.env.CAPTURE,JSON.stringify(process.argv.slice(2)))\n');
    const script=fileURLToPath(new URL('../../scripts/probe-native-arm64-alpine.sh',import.meta.url));
    const env={...process.env,PATH:bin+path.delimiter+process.env.PATH,RUNNER_ARCH:'ARM64',RSRS_DATA_DIR:data,RSRS_CPU_OWNED_ORT_FILE:'',CAPTURE:capture};
    const run=extra=>spawnSync('bash',[script,'aarch64-unknown-linux-musl',exe,models,path.join(root,'container profile'),runtime,'a'.repeat(64),'1.0.21-dev.5'],{env:{...env,...extra},encoding:'utf8'});
    for(const [extra,selected] of [[{},cached],[{RSRS_CPU_OWNED_ORT_FILE:custom},custom]]){
      const result=run(extra);assert.equal(result.status,0,result.stderr);const args=JSON.parse(readFileSync(capture));
      assert(args.includes(selected+':/cpu-model.ort:ro'));assert(args.includes(models+':/models:ro'));assert(args.includes('RSRS_CPU_OWNED_ORT_FILE=/cpu-model.ort'));assert.equal(args[args.indexOf('--network')+1],'none');
      assert(args.includes(bundle+':/runtime:ro'));assert(args.includes(receipt+':/runtime-selection.json:ro'));assert(!args.some(arg=>arg.startsWith('RSRS_RUNTIME_BIN=')));
      assert(args.includes('RSRS_RUNTIME_TRIPLE=aarch64-unknown-linux-musl'));
      assert(args.includes('NATIVE_RUNTIME_SHA256='+'a'.repeat(64)));assert(args.includes('NATIVE_RUNTIME_VERSION=1.0.21-dev.5'));
      rmSync(capture);
    }
    rmSync(cached);writeFileSync(local,'fixture');assert.equal(run({}).status,0);assert(JSON.parse(readFileSync(capture)).includes(local+':/cpu-model.ort:ro'));rmSync(capture);
    assert.notEqual(run({FAKE_HASH_STATUS:'1'}).status,0);assert(!existsSync(capture));
    rmSync(local);assert.notEqual(run({}).status,0);assert(!existsSync(capture));
    // Explicit missing override must not silently fall back to another model.
    writeFileSync(local,'fixture');assert.notEqual(run({RSRS_CPU_OWNED_ORT_FILE:path.join(root,'missing.ort')}).status,0);assert(!existsSync(capture));
    rmSync(path.join(bundle,'core-runtime.json'));assert.notEqual(run({}).status,0);assert(!existsSync(capture));
  }finally{rmSync(root,{recursive:true,force:true});}
});

test('critical and legacy full inventories cannot be interchanged or weakened by skipped native jobs',()=>{
  assert.equal(new Set(manifest.targets.map(t=>t.triple)).size,manifest.targets.length);
  assert.equal(manifest.targets.length,7,'dev.4 requires seven CLI targets; Runtime/SDK inventories remain separate');
  assert(manifest.targets.some(t=>t.triple==='aarch64-unknown-linux-musl'&&t.pkg==='@rsrsai/linux-arm64'));
  assert(!manifest.targets.some(t=>t.triple==='x86_64-apple-darwin'||t.pkg==='@rsrsai/macos-x64'));
  const critical=regressionContract(manifest,'critical');
  assert.equal(validationProfile(), 'full');assert.throws(()=>validationProfile('unknown'));
  assert.equal(critical.native.length,manifest.targets.length);assert.equal(critical.cloud.length,0);assert.equal(critical.migration.length,0);assert.equal(critical.migration_gate.length,0);assert.equal(critical.api,true);
  validateRegressionContract(critical,manifest,'critical');validateRegressionContract(contract,manifest,'full');
  assert.throws(()=>validateRegressionContract(critical,manifest,'full'));assert.throws(()=>validateRegressionContract(contract,manifest,'critical'));
  const unlabelled=copy(critical);delete unlabelled.validation_profile;assert.throws(()=>validateRegressionContract(unlabelled,manifest));
  const jobs=[...critical.native.map(t=>job('native-regression / Native ('+t+')')),job('api-smoke')];
  assert.equal(regressionStatus(jobs,critical),'success');assert.equal(regressionStatus(jobs,contract),'pending');
  for(const conclusion of ['failure','cancelled','skipped']){const changed=copy(jobs);changed[0].conclusion=conclusion;assert.throws(()=>regressionStatus(changed,critical))}
  const absent=copy(jobs);absent.shift();assert.equal(regressionStatus(absent,critical),'pending');
  assert.throws(()=>regressionStatus([...jobs,jobs[0]],critical));
  const foreign=copy(jobs);foreign[0].name='native-regression / Native (foreign-target)';assert.throws(()=>regressionStatus(foreign,critical));
});

test('only explicit inactive full matrices are ignored by critical and never enter its completion clock',()=>{
  const critical=regressionContract(manifest,'critical');
  const jobs=[...critical.native.map(t=>({...job('native-regression / Native ('+t+')'),started_at:'2026-11-01T00:00:00Z',completed_at:'2026-11-01T00:01:00Z'})),{...job('api-smoke'),started_at:'2026-11-01T00:00:00Z',completed_at:'2026-11-01T00:01:00Z'}];
  const skipped=name=>({name,status:'completed',conclusion:'skipped'});
  const inactive=[skipped('Native migration (${{ matrix.target }})'),skipped('Migration gate (${{ matrix.target }})')];
  // Exact names from GitHub API run 41291097685 attempt1, read during this change.
  const caller=skipped('native-regression'),cloud=skipped('cloud-sweep');
  const all=[...jobs,...inactive,caller,cloud];
  assert.throws(()=>regressionStatus([...jobs,skipped('native-regression / Native (${{ matrix.target }})')],critical));
  assert.equal(regressionStatus(all,critical),'success');assert.equal(regressionCompletedAt(all,critical,'2026-11-01T00:00:30Z'),Date.parse('2026-11-01T00:01:00Z'));
  assert.throws(()=>regressionStatus([...all,inactive[0]],critical));
  for(const state of [{status:'completed',conclusion:'failure'},{status:'in_progress',conclusion:null},{status:'completed',conclusion:null}])assert.throws(()=>regressionStatus([...jobs,{...inactive[0],...state}],critical));
  assert.throws(()=>regressionStatus([...jobs,skipped('Native migration (foreign-target)')],critical));
  const individual=skipped('Native migration (aarch64-apple-darwin)');assert.equal(regressionStatus([...jobs,individual],critical),'success');
  assert.throws(()=>regressionStatus([...jobs,individual,individual],critical));
  assert.throws(()=>regressionStatus([...jobs,{...individual,conclusion:'failure'}],critical));
  assert.throws(()=>regressionStatus([...inventory(),...inactive],contract));
});

test('workflow defaults critical, retains mandatory profile gates and dispatches nonpublishing daily full',()=>{
  const release=readFileSync(new URL('../../.github/workflows/release.yml',import.meta.url),'utf8').replace(/\r\n/g,'\n');
  const native=readFileSync(new URL('../../.github/workflows/release-native-validation.yml',import.meta.url),'utf8').replace(/\r\n/g,'\n');
  const guard=release.split('\n').find(line=>line.includes("if(['latest','stable'].includes(channel))"));
  assert(guard,'stable planning must fail closed before any reservation or output');
  for(const channel of ['latest','stable'])assert.throws(()=>runInNewContext(guard,{channel}),/complete G1/);
  runInNewContext(guard,{channel:'dev'});
  assert(release.indexOf(guard)<release.indexOf("if(channel==='dev'&&process.env.RELEASE_PUBLISH==='true')"));
  const daily=readFileSync(new URL('../../.github/workflows/release-full-regression.yml',import.meta.url),'utf8');
  assert.match(release,/validation_profile:[\s\S]*?default: critical/);assert.match(release,/REQUIRE_FULL:.*inputs.full_regression_before_publish/);
  assert.match(release,/process.env.REQUIRE_FULL==='true'\?'full':requested/);
  const part=name=>release.split('\n  '+name+':\n')[1]?.split(/\n  [a-z][\w-]*:\n/)[0];
  for(const name of ['validate','native-regression','native-regression-critical','native-regression-critical-readonly'])assert.match(part(name),/permissions:[\s\S]*?actions: read/);
  const standalone=readFileSync(new URL('../../.github/workflows/release-validation.yml',import.meta.url),'utf8').replace(/\r\n/g,'\n');
  assert.match(standalone,/permissions:\n  contents: read\n  actions: read/);
  assert.match(standalone.split('\n  native-regression:\n')[1].split('\n  npm-dry-run:')[0],/permissions:[\s\S]*?actions: read/);
  assert.match(part('native-regression'),/needs: \[plan, validate, artifact-inputs, published-assets-verification\]/);assert.match(part('native-regression'),/validation_profile: full/);
  assert.match(part('native-regression-critical'),/name: native-regression/);assert.match(part('native-regression-critical'),/needs: plan/);assert.match(part('native-regression-critical'),/validation_profile: critical/);
  for(const name of ['cloud-sweep','native-migration','migration-gate'])assert.match(part(name),/validation_profile == 'full'/);
  assert.doesNotMatch(part('api-smoke'),/validation_profile == 'full'/);
  assert.match(part('publication-ready'),/regressionContract\(require\('.\/npm\/artifact-manifest.json'\),process.env.VALIDATION_PROFILE\)/);
  assert.doesNotMatch(part('publication-ready'),/channel == 'latest' \|\| github.event_name/);
  assert.match(native,/default: full/);assert(native.includes('--profile critical'));
  assert(native.indexOf('Target producer concluded')<native.indexOf('const artifacts=inventory.artifacts.filter'));
  assert.match(native,/artifacts.length>1/);assert.match(native,/current.run_attempt!==attempt/);assert.match(native,/job.conclusion==='success'/);
  assert.match(native,/if: inputs.validation_profile == 'full'[\s\S]*?resident-stress/);
  assert.match(daily,/schedule:/);assert.match(daily,/-f publish=false -f validation_profile=full/);assert.doesNotMatch(daily,/-f publish=true(?:\s|$)|npm publish/);
});

test('critical cache writers and readers are mutually exclusive and full callers stay read-only',()=>{
  const text=file=>readFileSync(new URL('../../.github/workflows/'+file,import.meta.url),'utf8').replace(/\r\n/g,'\n');
  const release=text('release.yml'),part=name=>release.split('\n  '+name+':\n')[1]?.split(/\n  [a-z][\w-]*:\n/)[0];
  const writer=part('native-regression-critical'),reader=part('native-regression-critical-readonly');
  assert.match(writer,/cache-mode: write/);assert.match(reader,/cache-mode: read/);assert.match(part('native-regression'),/cache-mode: read/);
  assert.match(text('release-validation.yml'),/^cache-mode: read$/m);
  assert.doesNotMatch(text('release-validation.yml').split('\n  native-regression:\n')[1].split('\n  npm-dry-run:')[0],/cache-mode: (?:write|write-only)/);
  assert.doesNotMatch(text('release-native-validation.yml'),/cache-mode:/);
  for(const block of [writer,reader]){
    assert.match(block,/name: native-regression/);assert.match(block,/needs: plan/);assert.match(block,/validation_profile: critical/);assert.match(block,/producer_prefix: 'validate \/ '/);
  }
  const condition=block=>block.match(/    if: \$\{\{ (.+) \}\}/)[1];
  for(const repository of ['risense-ai/respire-cli','foreign/repo'])for(const ref of ['refs/heads/main','refs/tags/v1.2.3'])for(const sameSha of [true,false])for(const event of ['push','workflow_dispatch','pull_request','workflow_run'])for(const profile of ['critical','full']){
    const context={github:{repository,ref,sha:'a'.repeat(40),event_name:event},inputs:{reuse_dev12_validation:false,prepared_run:''},needs:{plan:{outputs:{sha:(sameSha?'a':'b').repeat(40),validation_profile:profile}}}};
    const write=runInNewContext(condition(writer),context),read=runInNewContext(condition(reader),context);
    assert.equal(Number(write)+Number(read),profile==='critical'?1:0,'exactly one critical native matrix may run');
    assert.equal(write,profile==='critical'&&repository==='risense-ai/respire-cli'&&ref==='refs/heads/main'&&sameSha&&['push','workflow_dispatch'].includes(event));
    for(const inputs of [{reuse_dev12_validation:true,prepared_run:''},{reuse_dev12_validation:false,prepared_run:'123'}]){
      assert.equal(runInNewContext(condition(writer),{...context,inputs}),false);assert.equal(runInNewContext(condition(reader),{...context,inputs}),false);
    }
  }
});

test('the actual critical target waiter binds unique successful producer, source, attempt and artifact before consumption',async()=>{
  const native=readFileSync(new URL('../../.github/workflows/release-native-validation.yml',import.meta.url),'utf8').replace(/\r\n/g,'\n');
  const program=native.split("          node - <<'NODE'\n")[1].split('\n          NODE')[0];
  async function run(mutate=()=>{}){
    const sha='a'.repeat(40),target='aarch64-apple-darwin';
    const state={run:{id:700,run_attempt:1,head_sha:sha,status:'in_progress'},jobs:{total_count:2,jobs:[{id:11,run_id:700,run_attempt:1,head_sha:sha,name:'validate / Release ('+target+')',status:'completed',conclusion:'success'},{name:'validate / Release (another-target)',status:'queued',conclusion:null}]},artifacts:{total_count:1,artifacts:[{id:9,name:'cli-release-'+target,expired:false,size_in_bytes:10,digest:'sha256:'+'b'.repeat(64),workflow_run:{id:700,head_sha:sha}}]}};
    mutate(state);const outputs=[],exits=[],errors=[];let artifactReads=0,queuedProducerReads=0,delays=0,now=0;
    await runInNewContext(program,{require:name=>name==='child_process'?{execFileSync:(_cmd,args)=>{const url=args[1];if(state.run.status==='queued'&&(url.endsWith('/artifacts?per_page=100')||url.endsWith('/jobs?per_page=100')))queuedProducerReads++;if(url.endsWith('/artifacts?per_page=100')){artifactReads++;return JSON.stringify(state.artifacts)}if(url.endsWith('/jobs?per_page=100'))return JSON.stringify(state.jobs);return JSON.stringify(state.run)}}:{appendFileSync:(_path,value)=>outputs.push(value)},process:{env:{GITHUB_REPOSITORY:'risense-ai/respire-cli',GITHUB_RUN_ID:'700',GITHUB_RUN_ATTEMPT:'1',GITHUB_SHA:sha,CLI_TARGET:target,PRODUCER_PREFIX:'validate / ',GITHUB_OUTPUT:'fixture-output'},exit:value=>exits.push(value)},console:{log:()=>{},error:value=>errors.push(value)},setTimeout:resolve=>{delays++;if(state.queued==='resume'){state.run.status='in_progress';resolve();return;}if(state.queued==='expire'){now=45*60*1000+1;resolve();return;}throw Error('still waiting; no target consumption')},Date:{now:()=>now}});
    return {outputs,exits,errors,artifactReads,queuedProducerReads,delays};
  }
  const good=await run();assert.deepEqual(good.outputs,['artifact_id=9\n']);assert.deepEqual(good.exits,[]);
  const mutations=[s=>s.jobs.jobs[0].id=0,s=>s.jobs.jobs[0].run_id=701,s=>s.jobs.jobs[0].run_attempt=2,s=>s.jobs.jobs[0].head_sha='c'.repeat(40),s=>s.run.run_attempt=2,s=>s.run.head_sha='c'.repeat(40),s=>s.run.status='completed',s=>s.jobs.total_count=3,s=>{s.jobs.jobs.push(s.jobs.jobs[0]);s.jobs.total_count++},s=>s.jobs.jobs[0].conclusion='failure',s=>s.jobs.jobs[0].conclusion='cancelled',s=>s.jobs.jobs[0].conclusion='skipped',s=>s.jobs.jobs[0].status='queued',s=>{s.artifacts.artifacts.push(s.artifacts.artifacts[0]);s.artifacts.total_count++},s=>s.artifacts.artifacts[0].expired=true,s=>s.artifacts.artifacts[0].workflow_run.id=701,s=>s.artifacts.artifacts[0].workflow_run.head_sha='c'.repeat(40),s=>s.artifacts.artifacts[0].digest='wrong',s=>s.artifacts.artifacts[0].id=0];
  for(const mutate of mutations){const bad=await run(mutate);assert.deepEqual(bad.outputs,[]);assert.deepEqual(bad.exits,[1])}
  const failed=await run(s=>s.jobs.jobs[0].conclusion='failure');assert.equal(failed.artifactReads,0,'an uploaded artifact never bypasses a failed producer');
  const queued=await run(s=>{s.run.status='queued';s.queued='resume'});
  assert.deepEqual(queued.outputs,['artifact_id=9\n']);assert.deepEqual(queued.exits,[]);assert.equal(queued.delays,1);assert.equal(queued.queuedProducerReads,0);
  const expired=await run(s=>{s.run.status='queued';s.queued='expire'});
  assert.deepEqual(expired.outputs,[]);assert.deepEqual(expired.exits,[1]);assert.equal(expired.artifactReads,0);assert.equal(expired.queuedProducerReads,0);assert.match(expired.errors[0],/unavailable within 45 minutes/);
  for(const status of ['completed','waiting','pending','unknown',undefined]){const bad=await run(s=>s.run.status=status);assert.deepEqual(bad.exits,[1]);assert.equal(bad.artifactReads,0);assert.match(bad.errors[0],/run status refused/)}
  for(const [field,value,label] of [['id',701,'run ID mismatch'],['run_attempt',2,'run attempt mismatch'],['head_sha','c'.repeat(40),'workflow SHA mismatch']]){
    const bad=await run(s=>{s.run[field]=value;s.run.status='queued';s.queued='resume'});assert.deepEqual(bad.exits,[1]);assert.equal(bad.delays,0);assert.match(bad.errors[0],new RegExp(label));
  }
});

function publishedFixture() {
  const part = kind => ({repository: `risense-ai/respire-${kind}`, release_id: kind === 'cli' ? 41 : 42,
    version: '1.0.21-dev.5', source_sha: (kind === 'cli' ? 'a' : 'b').repeat(40), producer:{run_id:91,run_attempt:2},
    assets: (kind === 'cli' ? manifest.targets.map(t=>t.triple) : Object.keys(JSON.parse(readFileSync(new URL('../../runtime-tests-source.json',import.meta.url))).targets)).flatMap((target, index) => publishedAssetNames(kind, target).map((name, n) =>
      ({id: index * 3 + n + 1, name, size: 12, sha256: 'c'.repeat(64)})))});
  const spec = {schema: 2, cli: part('cli'), runtime: part('runtime')};
  const text = JSON.stringify(spec), hash = createHash('sha256').update(text).digest('hex');
  return {spec, env: {ARTIFACT_SOURCE: 'published-assets', PUBLISHED_ASSETS: text, PUBLISHED_ASSETS_SHA256: hash,
    GITHUB_EVENT_NAME: 'workflow_dispatch', GITHUB_REPOSITORY: 'risense-ai/respire-cli', REQUEST_PUBLISH: 'false',
    VALIDATION_PROFILE: 'full', GITHUB_SHA: 'e'.repeat(40), RELEASE_REF: 'e'.repeat(40)}};
}
test('published assets require explicit full, immutable manifest and no publication/preparation/recovery', () => {
  const {spec, env} = publishedFixture(), targets = manifest.targets.map(t => t.triple);
  assert.deepEqual(validateArtifactRequest(env, targets), spec);
  assert.equal(validateArtifactRequest({}, targets), null);
  assert.equal(validateArtifactRequest({ARTIFACT_SOURCE: 'build'}, targets), null);
  for (const [key, value] of [['ARTIFACT_SOURCE', 'unknown'], ['GITHUB_EVENT_NAME', 'push'],
    ['GITHUB_REPOSITORY', 'fork/respire-cli'], ['REQUEST_PUBLISH', 'true'], ['REQUEST_PUBLISH', ''],
    ['VALIDATION_PROFILE', 'critical'], ['DEV_VERSION', spec.cli.version], ['PREPARED_RUN', '123'],
    ['REUSE_DEV12', 'true'], ['REPAIR_DEV12', 'true'], ['REPAIR_DEV14', 'true'], ['RESUME_DEV6', 'true'],
    ['RELEASE_REF', 'main'], ['RELEASE_REF', spec.cli.source_sha], ['GITHUB_SHA', 'main'], ['GITHUB_SHA', 'c'.repeat(40)], ['PUBLISHED_ASSETS_SHA256', 'd'.repeat(64)],
    ['PUBLISHED_ASSETS', env.PUBLISHED_ASSETS + '\n']]) {
    assert.throws(() => validateArtifactRequest({...env, [key]: value}, targets), key);
  }
  assert.throws(() => validateArtifactRequest({...env, ARTIFACT_SOURCE: 'build'}, targets));
  for (const change of [s => s.schema = 1, s => s.cli.producer.run_id = 0, s => delete s.runtime.producer, s => s.cli.repository = 'fork/respire-cli',
    s => s.cli.source_sha = 'main', s => s.runtime.release_id = 0, s => s.cli.version = 'dev',
    s => s.cli.assets.pop(), s => s.runtime.assets.push(s.runtime.assets[0]),
    s => s.cli.assets[1].id = s.cli.assets[0].id, s => s.cli.assets[1].name = s.cli.assets[0].name,
    s => s.runtime.assets[0].sha256 = 'bad', s => s.runtime.assets[0].size = 0,
    s => s.cli.assets[0].name = '../escape', s => s.cli.assets[0].extra = 'unbound',
    s => s.cli.assets[0].size = 2 ** 20 + 1, s => s.runtime.assets[0].size = 2 ** 31 + 1]) {
    const bad = copy(spec); change(bad); const text = JSON.stringify(bad);
    assert.throws(() => parsePublishedAssets(text, createHash('sha256').update(text).digest('hex'), targets));
  }
  assert.throws(() => parsePublishedAssets(env.PUBLISHED_ASSETS, env.PUBLISHED_ASSETS_SHA256, targets.slice(1)));
  assert.throws(() => parsePublishedAssets(env.PUBLISHED_ASSETS, env.PUBLISHED_ASSETS_SHA256, targets.map(() => targets[0])));
});
test('published mode cannot enter any build/prepared/publication/recovery job or claim full after download', () => {
  const workflow = readFileSync(new URL('../../.github/workflows/release.yml', import.meta.url), 'utf8').replace(/\r\n/g, '\n');
  const jobs = Object.fromEntries([...workflow.slice(workflow.indexOf('jobs:\n') + 6).matchAll(/^  ([a-z][a-z0-9-]+):\n([\s\S]*?)(?=^  [a-z][a-z0-9-]+:|$(?![\s\S]))/gm)].map(m => [m[1], m[2]]));
  for (const [name, body] of Object.entries(jobs)) {
    if (['artifact-inputs', 'published-assets-verification', 'published-full-complete', 'validate', 'native-regression', 'cloud-sweep', 'native-migration', 'migration-gate', 'api-smoke'].includes(name)) continue;
    const condition = body.match(/^    if: \$\{\{ (.*?) \}\}$/m)?.[1];
    assert.ok(condition, name);
    const suffix = " && (inputs.artifact_source || 'build') == 'build'";
    assert.ok(condition.endsWith(suffix), name + ' must be build-only');
    const original = condition.slice(0, -suffix.length);
    for (const artifact_source of [undefined, 'build', 'published-assets']) {
      const context = {inputs: {artifact_source, publish: true, validation_profile: 'full'},
        github: {event_name: 'workflow_dispatch', repository: 'risense-ai/respire-cli', ref: 'refs/heads/main', sha: 's'},
        always: () => true, cancelled: () => false,
        needs: new Proxy({}, {get: () => ({result: 'success', outputs: {publish: 'true', validation_profile: 'full', sha: 's'}})})};
      const js = value => value.replace(/needs\.([a-z][a-z0-9-]*)/g, (_, name) => `needs[${JSON.stringify(name)}]`);
      const actual = runInNewContext(js(condition), context);
      if (artifact_source === 'published-assets') assert.equal(Boolean(actual), false, name);
      else assert.equal(Boolean(actual), Boolean(runInNewContext(js(original), context)), name + ' default build behavior changed');
    }
  }
  const verification = jobs['published-assets-verification'];
  const actualNeeds = [...verification.matchAll(/^    needs: (.+)$/gm)].map(m => m[1]);
  assert.deepEqual(actualNeeds, ['artifact-inputs'], 'verification must depend only on the validated input job');
  const conditions = [...verification.matchAll(/^    if: \$\{\{ (.*?) \}\}$/gm)].map(m => m[1]);
  assert.equal(conditions.length, 1);
  assert.equal(conditions[0], "always() && needs.artifact-inputs.result == 'success' && inputs.artifact_source == 'published-assets'");
  const expression = conditions[0].replace(/needs\.([a-z][a-z0-9-]*)/g, (_, name) => `needs[${JSON.stringify(name)}]`);
  for (const result of ['success', 'failure', 'cancelled', 'skipped', undefined]) {
    for (const artifact_source of ['published-assets', 'build', undefined, 'unknown']) {
      const needs = new Proxy({'artifact-inputs': {result}}, {get(target, key) {
        assert.equal(key, 'artifact-inputs', 'verification referenced an undeclared dependency');
        return target[key];
      }});
      assert.equal(Boolean(runInNewContext(expression, {always: () => true, needs, inputs: {artifact_source}})),
        result === 'success' && artifact_source === 'published-assets');
    }
  }
  for (const name of ['artifact-inputs', 'published-assets-verification']) {
    const checkouts = [...jobs[name].matchAll(/      - uses: actions\/checkout@v5\n        with:\n([\s\S]*?)(?=      - |$)/g)];
    assert.equal(checkouts.length, 1);
    assert.match(checkouts[0][1], /^          ref: \$\{\{ github.sha \}\}$/m);
    assert.doesNotMatch(checkouts[0][1], /inputs\.ref|source_sha/);
  }
  assert.match(jobs.plan, /needs: artifact-inputs/);
  assert.match(jobs['published-assets-verification'], /contents: read/);
  assert.doesNotMatch(jobs['published-assets-verification'], /actions\/cache|cargo |set-build-version|next-dev-version|download-artifact/);
  assert.match(jobs['published-full-complete'], /--complete-published full-reports/);
  assert.match(jobs['published-full-complete'], /actual process image digests/);
  assert.match(jobs['published-full-complete'], /Object.values\(n\).some\(j=>j.result!=='success'\)/);
  for(const name of ['validate','native-regression','cloud-sweep','native-migration','migration-gate','api-smoke']) {
    const body=jobs[name], condition=body.match(/^    if: \$\{\{ (.*?) \}\}$/m)[1];
    const expr=condition.replace(/needs\.([a-z][a-z0-9-]*)/g,(_,id)=>`needs[${JSON.stringify(id)}]`);
    for(const result of ['success','failure','cancelled','skipped']) {
      const needs=new Proxy({'artifact-inputs':{result},'published-assets-verification':{result:'success'},plan:{result:'skipped',outputs:{}}},{get:(t,k)=>t[k]??{result:'success',outputs:{}}});
      assert.equal(Boolean(runInNewContext(expr,{always:()=>true,needs,inputs:{artifact_source:'published-assets'}})),result==='success',name);
    }
    assert.match(body,/needs: \[.*artifact-inputs.*published-assets-verification/);
    assert.match(jobs['published-full-complete'],new RegExp('needs: \\[.*'+name));
  }
});

test('published macOS ARM alias preserves the exact Mach-O 64-bit ARM64 header requirement',()=>{
  const root=mkdtempSync(path.join(tmpdir(),'published-macho-header-'));
  const image=path.join(root,'image'), alias='aarch64-apple-darwin';
  const macho=(magic=0xfeedfacf,cpu=0x100000c)=>{const b=Buffer.alloc(64);b.writeUInt32LE(magic,0);b.writeUInt32LE(cpu,4);return b;};
  try {
    writeFileSync(image,macho());
    for(const target of [alias,['aarch64','apple','darwin'].join('-')])assert.doesNotThrow(()=>verifyBinary(image,target));
    for(const bytes of [macho(0xfeedfacf,0x1000007),macho(0xfeedfacf,12),macho(0xfeedface,12),macho(0xbebafeca,0x100000c),macho(0xcafebabe,0x100000c),macho(0xcffaedfe,0xc000001),Buffer.from('\x7fELF'.padEnd(64,'\0')),Buffer.from('MZ'.padEnd(64,'\0'))]) {
      writeFileSync(image,bytes);assert.throws(()=>verifyBinary(image,alias));
    }
    writeFileSync(image,macho());
    for(const target of [alias+'x','x'+alias,'wsedw32-uubqy-qvasSc'])assert.throws(()=>verifyBinary(image,target));
  } finally {rmSync(root,{recursive:true,force:true});}
});

test('published validation exports product identity without overwriting the harness checkout SHA',()=>{
  const root=mkdtempSync(path.join(tmpdir(),'published-output-contract-'));
  try {
    const {spec,env}=publishedFixture(),output=path.join(root,'output');writeFileSync(output,'sha='+env.GITHUB_SHA+'\n');
    const result=spawnSync(process.execPath,['npm/scripts/extract-artifact.mjs','--validate-published'],{cwd:fileURLToPath(new URL('../../',import.meta.url)),env:{...process.env,...env,GITHUB_OUTPUT:output},encoding:'utf8'});
    assert.equal(result.status,0,result.stderr);
    const lines=readFileSync(output,'utf8').trim().split('\n');
    assert.deepEqual(lines,['sha='+env.GITHUB_SHA,'product_sha='+spec.cli.source_sha,'version='+spec.cli.version]);
    const parent=readFileSync(new URL('../../.github/workflows/release.yml',import.meta.url),'utf8');
    assert.match(parent,/sha: \$\{\{ steps.validated.outputs.product_sha \}\}/);
    const reusable=readFileSync(new URL('../../.github/workflows/release-validation.yml',import.meta.url),'utf8');
    const published=reusable.split('if [ "$ARTIFACT_SOURCE" = published-assets ]; then')[1].split('fi')[0];
    assert.match(published,/--validate-published/);assert.doesNotMatch(published,/BUILD_VERSION|set-build-version|next-dev-version/);
  } finally {rmSync(root,{recursive:true,force:true});}
});

test('published consumers declare every condition dependency and cannot execute compile/cache or original staging steps',()=>{
  const root=new URL('../../.github/workflows/',import.meta.url),text=name=>readFileSync(new URL(name,root),'utf8').replace(/\r\n/g,'\n');
  const workflow=text('release.yml'),jobs=Object.fromEntries([...workflow.slice(workflow.indexOf('jobs:\n')+6).matchAll(/^  ([a-z][a-z0-9-]+):\n([\s\S]*?)(?=^  [a-z][a-z0-9-]+:|$(?![\s\S]))/gm)].map(m=>[m[1],m[2]]));
  const js=expr=>expr.replace(/needs\.([a-z][a-z0-9-]*)/g,(_,name)=>`needs[${JSON.stringify(name)}]`);
  for(const name of ['validate','native-regression','cloud-sweep','native-migration','migration-gate','api-smoke']) {
    const body=jobs[name],dependencies=body.match(/^    needs: \[(.+)\]$/m)[1].split(',').map(v=>v.trim());
    const condition=body.match(/^    if: \$\{\{ (.+) \}\}$/m)[1];
    const make=(mode,failed)=>new Proxy(Object.fromEntries(dependencies.map(id=>[id,{result:id===failed?'failure':id==='plan'&&mode==='published-assets'?'skipped':id==='published-assets-verification'&&mode==='build'?'skipped':'success',outputs:{validation_profile:'full'}}])),{get(t,key){assert(dependencies.includes(key),'undeclared '+name+' dependency '+key);return t[key];}});
    for(const mode of ['build','published-assets']) {
      const context={always:()=>true,needs:make(mode),inputs:{artifact_source:mode,reuse_dev12_validation:false,prepared_run:''}};
      assert.equal(Boolean(runInNewContext(js(condition),context)),true,name+' '+mode);
      const required=mode==='published-assets'?['artifact-inputs','published-assets-verification',...(name==='native-regression'?['validate']:[]),...(name==='migration-gate'?['cloud-sweep','native-migration']:[])]:dependencies.filter(id=>!['artifact-inputs','published-assets-verification'].includes(id));
      for(const failed of required)assert.equal(Boolean(runInNewContext(js(condition),{...context,needs:make(mode,failed)})),false,name+' accepted failed '+failed);
    }
  }
  const validation=text('release-validation.yml'),binaries=validation.split('\n  binaries:\n')[1].split('\n  native-regression:')[0];
  for(const step of binaries.split(/(?=^      - )/m)) {
    if(!/dtolnay\/rust-toolchain|rust-ci-cache|build-linux-musl|fetch-core-sdk|stage-core-runtime|stage-artifacts|set-build-version/.test(step))continue;
    const condition=step.match(/^        if: (.+)$/m)?.[1];assert(condition,'build step lacks a mode guard');
    const expr=condition.replace(/^\$\{\{ /,'').replace(/ \}\}$/,'');
    assert.equal(Boolean(runInNewContext(expr,{inputs:{artifact_source:'published-assets'},contains:()=>false})),false);
  }
  assert.match(validation,/--pack-published published-raw/);
  assert.match(validation,/pattern: published-assets-verification-\*/);
  const native=text('release-native-validation.yml');
  const nativeDefault=native.split('\njobs:\n')[0];
  assert.doesNotMatch(nativeDefault,/GH_TOKEN:|GITHUB_TOKEN:|contents: write/);
  assert.match(nativeDefault,/permissions:\n  contents: read/);
  const nativeJobs=Object.fromEntries([...native.split('\njobs:\n')[1].matchAll(/^  ([a-z][a-z0-9-]+):\n([\s\S]*?)(?=^  [a-z][a-z0-9-]+:|$(?![\s\S]))/gm)].map(m=>[m[1],m[2]]));
  assert.deepEqual(Object.keys(nativeJobs).filter(name=>/contents: write/.test(nativeJobs[name])),[]);
  assert.match(nativeJobs.native,/permissions:\n      contents: read\n      actions: read/);
  assert.doesNotMatch(nativeJobs.native,/contents: write|actions: write|id-token:/);
  assert.doesNotMatch(native,/historical-draft-download|draft-baseline-cache/);
  assert.doesNotMatch(nativeJobs.native,/^    needs:/m);
  assert(nativeJobs.native.includes('--profile critical'));
  const upgrade=readFileSync(new URL('../../scripts/test-published-upgrades.py',import.meta.url),'utf8').replace(/\r\n/g,'\n');
  assert.match(upgrade,/if args.download_only:\n        assert tag=='v1\.0\.10' and release\['draft'\][\s\S]*?\n        return\n    with tarfile\.open/);
  assert.match(upgrade,/if args.download_only:\n    assert args.profile=='full' and not args.draft_baseline_cache[\s\S]*?\n    sys.exit\(0\)\n\ntry:/);
  assert.match(upgrade,/if release\['draft'\] and args.draft_baseline_cache:\n        assert not needed/);
  const extract=native.split('      - name: Verify and extract the release binary\n')[1].split('\n      - ')[0];
  assert.match(extract,/GH_TOKEN: \$\{\{ github.token \}\}/);
  const account=readFileSync(new URL('../../scripts/test-real-m3-account-switch.py',import.meta.url),'utf8');
  assert.match(account,/env = \{key: value for key, value in os.environ.items\(\)\s+if key not in \('GH_TOKEN', 'GITHUB_TOKEN'\)\}/);
  assert.match(account,/seed_env=\{\*\*env,/);
  assert.match(account,/web_help=subprocess\.check_output\(\[args.seed_binary,'web','--help'\],env=seed_env,/);
  assert.doesNotMatch(account,/os\.environ\.(?:pop|clear|update)\(/);
  assert.doesNotMatch(validation.split('\njobs:\n')[0],/GH_TOKEN:|GITHUB_TOKEN:/);
  const consume=validation.split('      - name: Consume only verified published release bytes\n')[1].split('\n      - ')[0];
  assert.match(consume,/GH_TOKEN: \$\{\{ github.token \}\}/);
  assert.match(validation,/GH_TOKEN='\$\{\{ github.token \}\}' node npm\/scripts\/extract-artifact.mjs --pack-published/);
  const login=readFileSync(new URL('../../scripts/dev-login-interruption-smoke.py',import.meta.url),'utf8');
  assert.match(login,/and k not in \("GH_TOKEN", "GITHUB_TOKEN"\)/);
  assert.doesNotMatch(login,/os\.environ\.(?:pop|clear|update)\(/);
  const sweep=readFileSync(new URL('../../scripts/dev-release-sweep.ps1',import.meta.url),'utf8');
  assert.match(sweep,/foreach \(\$tokenName in @\('GH_TOKEN', 'GITHUB_TOKEN'\)\)\s*\{\s*\[void\]\$psi.Environment.Remove\(\$tokenName\)/);
});
