import test from 'node:test';
import assert from 'node:assert/strict';
import {runInNewContext} from 'node:vm';
import {readFileSync,mkdtempSync,mkdirSync,writeFileSync,existsSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {regressionContract,validateRegressionContract,validationProfile,regressionStatus,regressionCompletedAt} from './release-regression-contract.mjs';
import {requireRegressions} from './cleanup-release-artifacts.mjs';
import {verifyBinary} from './verify-binary.mjs';
import {createHash} from 'node:crypto';
const manifest=JSON.parse(readFileSync(new URL('../artifact-manifest.json',import.meta.url)));
const contract=regressionContract(manifest),copy=structuredClone;
const job=name=>({name,status:'completed',conclusion:'success'});
const inventory=()=>[...contract.native.map(t=>job(`native-regression / Native (${t})`)),...contract.cloud.map(t=>job(`cloud-sweep (runner, ${t})`)),...contract.migration.map(t=>job(`Native migration (${t})`)),...contract.migration_gate.map(t=>job(`Migration gate (${t})`)),job('api-smoke'),job('publish')];
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
test('both Linux ARM targets require native runners, every source feedback phase and background install proof',()=>{
  const text=file=>readFileSync(new URL('../../.github/workflows/'+file,import.meta.url),'utf8');
  for(const file of ['ci.yml','release-validation.yml','release-native-validation.yml','release.yml']){
    const workflow=text(file).replace(/\r\n/g,'\n');
    for(const triple of ['aarch64-unknown-linux-gnu','aarch64-unknown-linux-musl'])assert(workflow.includes('os: ubuntu-24.04-arm\n            target: '+triple),file+' missing native ARM target '+triple);
    assert(workflow.includes('scripts/require-native-linux-arm64.sh'),file+' lacks hardware check');
  }
  const source=text('token-free-sdk-check.yml');assert.match(source,/if: \$\{\{ !contains\(inputs.target, '-musl'\) \}\}/);
  assert.match(source,/run: bash scripts\/build-linux-musl.sh \$\{\{ inputs.target \}\}/);
  assert.match(source,/inputs.feedback_probe && contains\(inputs.target, '-musl'\)/);
  assert.match(source,/scripts\/verify-linux-arm64-elf.sh/);assert.match(source,/diary_tests/);assert.match(source,/feedback_contract_probe/);
  assert.match(source,/scripts\/probe-native-arm64-alpine.sh/);
  for(const file of ['ci.yml','release-native-validation.yml'])assert.match(text(file),/scripts\/probe-native-arm64-alpine.sh/);
  const alpine=readFileSync(new URL('../../scripts/probe-native-arm64-alpine.sh',import.meta.url),'utf8');
  assert.match(alpine,/--network none/);assert.match(alpine,/--direct model probe --json/);
  assert.match(alpine,/RSRS_CPU_OWNED_ORT_FILE=\/cpu-model\.ort/);assert.equal((alpine.match(/sha256sum -c -s/g)||[]).length,3);
  assert.doesNotMatch(alpine,/--check|--status/);
  assert.match(alpine,/--runtime-internal --stop --json/);
  assert(alpine.indexOf('test -r /cpu-model.ort')<alpine.indexOf('--direct model probe'),'mounted CPU artifact must be checked before inference');
  assert.match(alpine,/test -z "\$\{RSRS_CORE_TEST_MODE:-\}"/);assert.doesNotMatch(alpine,/-e (?:GH_TOKEN|GITHUB_TOKEN|CORE_SDK_READ_TOKEN|RSRS_CORE_TEST_MODE)/);
  const background=text('verify-publication.yml').split('  verify-publication-arm64:')[1];
  assert.match(background,/runs-on: ubuntu-24.04-arm/);assert.match(background,/VERIFY_ARM64: 'true'/);
  assert.match(background,/publication-arm64-verified-/);assert.doesNotMatch(background,/id-token:|contents: write|actions: write|npm publish|concurrency:/);
  const native=text('release-native-validation.yml').replace(/\r\n/g,'\n');
  const step=name=>native.split('      - name: '+name+'\n')[1]?.split('\n      - ')[0];
  const install=step('Install and verify the official pinned standalone Runtime');
  assert.match(install,/id: pinned-runtime/);assert.doesNotMatch(install,/^        if:/m);
  assert(native.indexOf('id: pinned-runtime')<native.indexOf('      - name: Install and probe BGE CPU inference'));
  const script=install.split("<<'NODE'\n")[1].split('\n          NODE')[0].replace(/^          /gm,'').replace(/^import .*;\n/gm,'');
  for(const platform of ['linux','win32']) {
    const p=platform==='win32'?path.win32:path.posix, root=platform==='win32'?'C:\\runner\\native-runtime':'/runner/native-runtime';
    const image=Buffer.from('synthetic installed Runtime; never executed'), version='1.0.21-dev.5';
    const digest=createHash('sha256').update(image).digest('hex'), metadata=JSON.stringify({triple:'synthetic-target',runtime_version:version});
    const simulate=change=>{
      const selected={version,sha256:digest,release:{metadata_json:metadata,metadata_sha256:createHash('sha256').update(metadata).digest('hex')}};
      const state={selected,status:0,sameImage:false,hosted:'true'};change?.(state);
      const tokenSentinel='fixture-only-value';
      const output=[],calls=[],env={GITHUB_ACTIONS:'true',RUNTIME_FIXTURE_HOSTED:state.hosted,CLI_TARGET:'synthetic-target',RUNNER_TEMP:p.dirname(root),GITHUB_OUTPUT:'fixture-output',GH_TOKEN:tokenSentinel,GITHUB_TOKEN:tokenSentinel};
      runInNewContext(script,{assert,createHash,join:p.join,resolve:(...parts)=>p.resolve(...parts),process:{platform,env},
        mkdirSync:()=>{},mkdtempSync:()=>root,statSync:()=>({isFile:()=>true}),
        realpathSync:file=>state.sameImage?'same-image':file,
        readFileSync:file=>file==='runtime-pin.json'?JSON.stringify({required:version}):file===p.join(root,'runtime.json')?JSON.stringify(selected):image,
        appendFileSync:(_file,line)=>output.push(line),
        spawnSync:(cli,args,options)=>{calls.push({cli,args:[...args],env:options.env});return {status:state.status}}});
      assert.equal(calls.length,1);assert.deepEqual(calls[0].args,['--json','runtime','install']);
      for(const token of ['GH_TOKEN','GITHUB_TOKEN']){assert.equal(calls[0].env[token],undefined);assert.equal(env[token],tokenSentinel);}
      assert.equal(calls[0].env.RSRS_DATA_DIR,root);assert.equal(calls[0].env.HOME,p.join(root,'home'));
      assert.equal(calls[0].env.RSRS_RUNTIME_TRIPLE,'synthetic-target');
      assert.deepEqual(output,[`path=${p.join(root,'runtime',version,'rsrs-runtime'+(platform==='win32'?'.exe':''))}\n`,`sha256=${digest}\n`,`version=${version}\n`]);
    };
    simulate();
    for(const change of [s=>s.status=1,s=>s.selected.version='1.0.21-dev.4',s=>s.selected.sha256='a'.repeat(64),
      s=>s.selected.release=null,s=>s.selected.release.metadata_sha256='b'.repeat(64),s=>s.sameImage=true,s=>s.hosted='false',
      s=>{s.selected.release.metadata_json=JSON.stringify({triple:'wrong-gnu-target',runtime_version:version});s.selected.release.metadata_sha256=createHash('sha256').update(s.selected.release.metadata_json).digest('hex');}])assert.throws(()=>simulate(change));
  }
  for(const name of ['Require every upgrade selected by the native validation profile','Verify resident foreground and background inference under concurrent CLI load']) {
    const consumer=step(name);
    for(const [key,output] of [['BIN','path'],['SHA256','sha256'],['VERSION','version']])assert(consumer.includes(`NATIVE_RUNTIME_${key}: \u0024{{ steps.pinned-runtime.outputs.${output} }}`));
    assert.match(consumer,/test -n "\$NATIVE_RUNTIME_BIN" && test -n "\$NATIVE_RUNTIME_SHA256" && test -n "\$NATIVE_RUNTIME_VERSION"/);
    assert.match(consumer,/--runtime-binary "\$NATIVE_RUNTIME_BIN" --runtime-sha256 "\$NATIVE_RUNTIME_SHA256" --runtime-version "\$NATIVE_RUNTIME_VERSION"/);
  }
  assert.match(step('Require every upgrade selected by the native validation profile'),/GH_TOKEN: \$\{\{ github.token \}\}/);
  assert.doesNotMatch(native,/RSRS_ARTIFACT_SOURCE: published-assets|RSRS_PUBLISHED_ASSETS_SHA256:|RSRS_PUBLISHED_BUNDLE_SHA256:/);
  const account=readFileSync(new URL('../../scripts/test-real-m3-account-switch.py',import.meta.url),'utf8');
  assert.match(account,/if key not in \('GH_TOKEN', 'GITHUB_TOKEN'\)/);
  assert.match(account,/web_help=subprocess\.check_output\(\[args.seed_binary,'web','--help'\],env=seed_env,/);
  const probe=step('Install and probe BGE CPU inference');
  assert.match(probe,/RSRS_RUNTIME_BIN: \$\{\{ steps.pinned-runtime.outputs.path \}\}/);
  assert.match(probe,/RSRS_RUNTIME_TRIPLE: \$\{\{ matrix.target \}\}/);
  assert.match(probe,/unset GH_TOKEN GITHUB_TOKEN/);
  assert.match(probe,/test -n "\$RSRS_RUNTIME_BIN" && test -n "\$NATIVE_RUNTIME_SHA256" && test -n "\$NATIVE_RUNTIME_VERSION"/);
  assert.match(probe,/probe-native-arm64-alpine.sh[^\n]+"\$RSRS_RUNTIME_BIN" "\$NATIVE_RUNTIME_SHA256" "\$NATIVE_RUNTIME_VERSION"/);
  assert.match(alpine,/-v "\$bundle:\/runtime:ro"/);assert.match(alpine,/-e RSRS_RUNTIME_BIN=\/runtime\/rsrs-runtime/);
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
  assert.match(migration,/needs: plan/);assert.doesNotMatch(migration,/needs:.*cloud-sweep|dev-smoke-gate.py|continue-on-error/);
  assert.match(migration,/dev-profile-migration-smoke.py/);assert.match(migration,/extract-artifact.mjs/);assert.match(migration,/verified-build.json/);
  assert.match(join,/needs: \[plan, cloud-sweep, native-migration\]/);assert.match(join,/base-release-sweep-/);assert.match(join,/native-profile-migration-fixture-/);
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
    const bundle=path.join(root,'complete musl runtime'),runtime=path.join(bundle,'rsrs-runtime');mkdirSync(bundle);
    writeFileSync(runtime,'fixture');writeFileSync(path.join(bundle,'core-runtime.json'),'fixture');
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
      assert(args.includes(bundle+':/runtime:ro'));assert(args.includes('RSRS_RUNTIME_BIN=/runtime/rsrs-runtime'));
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
  assert.equal(manifest.targets.length,7,'dev.5 releases seven platforms; SDK/G1 inventories remain separate');
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
  assert.match(part('native-regression'),/needs: \[plan, validate\]/);assert.match(part('native-regression'),/validation_profile: full/);
  assert.match(part('native-regression-critical'),/name: native-regression/);assert.match(part('native-regression-critical'),/needs: plan/);assert.match(part('native-regression-critical'),/validation_profile: critical/);
  for(const name of ['cloud-sweep','native-migration','migration-gate'])assert.match(part(name),/validation_profile == 'full'/);
  assert.doesNotMatch(part('api-smoke'),/validation_profile == 'full'/);
  assert.match(part('publication-ready'),/regressionContract\(require\('.\/npm\/artifact-manifest.json'\),process.env.VALIDATION_PROFILE\)/);
  assert.doesNotMatch(part('publication-ready'),/channel == 'latest' \|\| github.event_name/);
  assert.match(native,/default: full/);assert(native.includes("--profile '${{ inputs.validation_profile }}'"));
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
