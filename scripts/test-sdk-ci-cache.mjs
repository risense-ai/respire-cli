import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {mkdtempSync,mkdirSync,writeFileSync,rmSync,symlinkSync,readFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,posix} from 'node:path';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {runInNewContext} from 'node:vm';
import {TARGETS,cacheKey,planCaches,auditSdkDirectory,canonicalEntry} from './sdk-ci-cache.mjs';
const version='1.0.2-dev.11';
function lock(version='1.0.2-dev.11'){return {schema_version:1,targets:Object.fromEntries(TARGETS.map(t=>{const base=`https://github.com/risense-ai/respire-core/releases/download/sdk-v${version}/respire-core-sdk-${t}`;return [t,{sdk_version:version,private_repository:'risense-ai/respire-core',release_tag:'sdk-v'+version,url:base+'.manifest.json',archive_url:base+'.tar.gz',manifest_sha256:'a'.repeat(64),archive_sha256:'b'.repeat(64),redistribution:'approved'}];}))};}
test('plan emits all canonical SDK identities with immutable target-specific keys',()=>{const a=lock(),b=lock();for(const e of Object.values(a.targets))e.unknown_secret='do-not-forward';const result=planCaches(a,b);assert.equal(result.include.length,TARGETS.length);assert(!JSON.stringify(result).includes('do-not-forward'));assert.equal(new Set(result.include.map(x=>x.key)).size,TARGETS.length);});
test('foreign repos, URLs, tags, unknown targets, missing hashes and differing locks are rejected',()=>{for(const [field,value] of [['private_repository','risense-ai/other'],['url','https://evil.invalid'],['release_tag','bad'],['archive_sha256','']]){const a=lock();a.targets[TARGETS[0]][field]=value;assert.throws(()=>planCaches(a,lock()));}const a=lock();a.targets.extra=a.targets[TARGETS[0]];assert.throws(()=>planCaches(a,lock()));const b=lock();b.targets[TARGETS[0]].archive_sha256='c'.repeat(64);assert.throws(()=>planCaches(lock(),b),/differ/);});
test('any pinned hash change gets a different key; no prefix fallback',()=>{const a=lock().targets[TARGETS[0]],b={...a,manifest_sha256:'c'.repeat(64)};assert.notEqual(cacheKey(TARGETS[0],a),cacheKey(TARGETS[0],b));});
test('SDK directory audit permits only exact manifest-listed bytes, never credentials/source extras',()=>{const dir=mkdtempSync(join(tmpdir(),'sdk-cache-audit-'));try{mkdirSync(join(dir,'lib'));const payload=Buffer.from('native fixture'),file={path:'lib/core.a',sha256:createHash('sha256').update(payload).digest('hex')};writeFileSync(join(dir,'lib/core.a'),payload);const m={target:TARGETS[0],sdk_version:version,abi_version:0x10002,inference_thread_contract:1,association_contract:1,models_bundled:false,redistribution:'permitted-under-included-license',files:[file]};const raw=Buffer.from(JSON.stringify(m));writeFileSync(join(dir,'manifest.json'),raw);const e={...lock().targets[TARGETS[0]],manifest_sha256:createHash('sha256').update(raw).digest('hex')};auditSdkDirectory(dir,TARGETS[0],e);writeFileSync(join(dir,'credential.env'),'fake-sensitive-data');assert.throws(()=>auditSdkDirectory(dir,TARGETS[0],e),/Unexpected/);rmSync(join(dir,'credential.env'));writeFileSync(join(dir,'lib/core.a'),'corrupt');assert.throws(()=>auditSdkDirectory(dir,TARGETS[0],e),/corrupt/);}finally{rmSync(dir,{recursive:true});}});
test('cache audit rejects links and unsafe manifest paths',()=>{const dir=mkdtempSync(join(tmpdir(),'sdk-cache-link-'));try{const m={target:TARGETS[0],sdk_version:version,abi_version:0x10002,inference_thread_contract:1,association_contract:1,models_bundled:false,redistribution:'permitted-under-included-license',files:[{path:'../outside',sha256:'a'.repeat(64)}]};const raw=Buffer.from(JSON.stringify(m));writeFileSync(join(dir,'manifest.json'),raw);const e={...lock().targets[TARGETS[0]],manifest_sha256:createHash('sha256').update(raw).digest('hex')};assert.throws(()=>auditSdkDirectory(dir,TARGETS[0],e),/Unsafe/);}finally{rmSync(dir,{recursive:true});}});
test('credential-bearing workflow uses only main tools; native receiver has no secret contract',()=>{const warm=readFileSync(new URL('../.github/workflows/private-sdk-cache.yml',import.meta.url),'utf8').replace(/\r\n/g,'\n');const native=readFileSync(new URL('../.github/workflows/token-free-sdk-check.yml',import.meta.url),'utf8').replace(/\r\n/g,'\n');assert(warm.includes("github.ref == 'refs/heads/main'"));assert.equal((warm.match(/secrets\.CORE_SDK_READ_TOKEN/g)||[]).length,1);const download=warm.split('\n  download:\n')[1].split('\n  native:\n')[0];assert(download.includes('ref: ${{ github.sha }}'));assert(!download.includes('inputs.reviewed_source_sha'));const receiver=warm.split('\n  native:\n')[1];assert(receiver.includes('uses: ./.github/workflows/token-free-sdk-check.yml'));assert(!/\n\s*secrets:/.test(receiver));assert(!/\n\s*secrets:/.test(native));assert(!native.includes('${{ secrets.'));assert(!warm.includes('upload-artifact'));
 const code=warm.split("node --input-type=module - <<'JS'\n")[1].split('          JS')[0].replace(/^[ \t]*import .+;[ \t]*$/gm,'');
 const cliPlan=planCaches(lock(),lock()),runtimePlan=planCaches(lock('2.0.0-dev.3'),lock('2.0.0-dev.3'));
 for(const runtime of [null,cliPlan,runtimePlan]){
  let output;
  runInNewContext(code,{readFileSync:name=>JSON.stringify(name.endsWith('runtime-plan.json')?runtime:cliPlan),appendFileSync:(name,value)=>{output=value;},
   process:{env:{RUNNER_TEMP:'/temp',GITHUB_OUTPUT:'/output',RUNTIME_SOURCE_SHA:runtime?'a'.repeat(40):''}}});
  const fields=Object.fromEntries(output.trim().split('\n').map(line=>{const at=line.indexOf('=');return [line.slice(0,at),JSON.parse(line.slice(at+1))];}));
  assert.equal(fields.matrix.include.length,runtime===runtimePlan?16:8);
  assert.deepEqual(fields.native.include.map(entry=>entry.key),cliPlan.include.filter(entry=>entry.target!=='aarch64-pc-windows-msvc').map(entry=>entry.key));
 }
 assert(warm.includes('repos/risense-ai/respire-runtime/contents/sdk/core-sdk.lock.json?ref=$RUNTIME_SOURCE_SHA'));assert(!native.includes('upload-artifact'));for(const file of ['ci.yml','release-validation.yml','accelerator.yml'])assert(!readFileSync(new URL('../.github/workflows/'+file,import.meta.url),'utf8').replace(/\r\n/g,'\n').includes('secrets.CORE_SDK_READ_TOKEN'));});
test('ordinary CLI source checks avoid SDK caches; explicit product checks require exact keys',()=>{
 for(const file of ['ci.yml','token-free-sdk-check.yml']){
  const text=readFileSync(new URL('../.github/workflows/'+file,import.meta.url),'utf8').replace(/\r\n/g,'\n');
  assert.doesNotMatch(text,/fetch-core-sdk/);
  if(file==='token-free-sdk-check.yml'){
   assert.doesNotMatch(text,/cmp <\(git show HEAD:sdk\/core-sdk.lock.json\) <\(git -C \.runtime-examples/);
   assert.equal((text.match(/verifyRuntimeSdkLock\(readPin\(\)\)/g)||[]).length,2);
   assert.equal((text.match(/cmp <\(git show HEAD:sdk\/core-sdk.lock.json\) <\(git show HEAD:crates\/core-sdk\/core-sdk.lock.json\)/g)||[]).length,2);
   assert.equal((text.match(/auditSdkDirectory\(sdk, target, canonicalEntry\(target, entry\)\)/g)||[]).length,2);
   for(const lane of text.split(/\n  (?:native-source|source-coverage):\n/).slice(1)){
    assert.match(lane,/test "\$\(git rev-parse HEAD\)" = "\$CLI_SOURCE_SHA"/);
    assert.match(lane,/cmp <\(git -C \.runtime-examples show HEAD:sdk\/core-sdk.lock.json\) <\(git -C \.runtime-examples show HEAD:crates\/core-sdk\/core-sdk.lock.json\)/);
    assert(lane.indexOf('auditSdkDirectory(')<lane.indexOf('node scripts/fetch-runtime-test-bundle.mjs fetch'));
    assert.match(lane,/RSRS_CORE_SDK_DIR: \$\{\{ env.RSRS_RUNTIME_CORE_SDK_DIR \}\}/);
    assert.doesNotMatch(lane,/restore-keys:|secrets\./);
   }
   assert.match(text,/-e RSRS_CORE_SDK_DIR="\/workspace\/\.runtime-examples\/\.sdk\/\$SDK_TARGET"/);
   assert.match(text,/export RSRS_CORE_SDK_DIR="\$RSRS_RUNTIME_CORE_SDK_DIR"/);
   const native=text.split('\n  source-coverage:\n')[0];
   const binding=native.split('- name: Bind Runtime example source to the verified SDK lock')[1];
   const program=binding.split("node --input-type=module <<'NODE'\n")[1].split('          NODE')[0].replace(/^[ \t]*import .+;[ \t]*$/gm,'');
   const runtimeLock=lock('2.0.0-dev.3');
   for(const target of TARGETS){
    const writes=[];let verified=false;
    runInNewContext(program,{assert,planCaches,readPin:()=>({source_sha:'a'.repeat(40)}),verifyRuntimeSdkLock:pin=>{assert.equal(pin.source_sha,'a'.repeat(40));verified=true;},
     readFileSync:file=>{assert(file.startsWith('.runtime-examples/'));return JSON.stringify(runtimeLock);},appendFileSync:(file,value)=>writes.push(value),
     process:{env:{SDK_TARGET:target,GITHUB_OUTPUT:'/output'}}});
    assert(verified);
    assert.deepEqual(writes,target==='x86_64-apple-darwin'?[]:[`key=${cacheKey(target,runtimeLock.targets[target])}\n`]);
   }
   for(const restore of native.split('- uses: actions/cache/restore@v4').slice(1)){
    const block=restore.split(/\n      - (?:name:|uses:)/)[0];
    assert.match(block,/if: inputs.feedback_probe && inputs.target != 'x86_64-apple-darwin'/);
   }
   assert.match(text,/cargo build --locked -p respire --bin rsrs/);
  } else {
   assert.doesNotMatch(text,/path: \.sdk\/|RSRS_CORE_SDK_DIR|CANDIDATE_MODE|runtime-integration:/);
   assert.match(text,/cargo test --locked -p respire_spawn/);
   assert.match(text,/unset GH_TOKEN GITHUB_TOKEN CORE_SDK_READ_TOKEN RSRS_RUNTIME_BIN/);
  }
  assert.doesNotMatch(text,/cargo (?:test|build) --workspace|--manifest-path \.runtime-examples/);
 }
 const text=readFileSync(new URL('../.github/workflows/accelerator.yml',import.meta.url),'utf8').replace(/\r\n/g,'\n');
 assert(text.includes('enableCrossOsArchive: true'));assert(text.includes('fail-on-cache-miss: true'));
 for(const section of text.split('- uses: actions/cache/restore@v4').slice(1)){
  const block=section.split(/\n      - (?:name:|uses:)/)[0];
  if(block.includes('path: .sdk/'))assert(!block.includes('restore-keys:'));
 }
});
test('CLI release validation has no native SDK preparation or redistribution',()=>{
 const text=readFileSync(new URL('../.github/workflows/release-validation.yml',import.meta.url),'utf8').replace(/\r\n/g,'\n');
 assert(text.includes('Prepare versioned CLI artifacts'));
 for(const forbidden of ['path: .sdk/','fetch-core-sdk.mjs','stage-core-runtime.mjs','check-sdk-release.mjs']) assert(!text.includes(forbidden),forbidden);
});

test('real model probe does not inherit the unit-test Core mode',()=>{
 const probe=readFileSync(new URL('./probe-native-arm64-alpine.sh',import.meta.url),'utf8');
 assert.doesNotMatch(probe,/(?:>|\bcat)\s+\/profile\/inference\.json/,'probe output must not create or truncate Runtime inference configuration');
 assert(probe.includes('> /profile/model-probe-result.json')&&probe.includes('"$profile/model-probe-result.json"'));
 assert(probe.includes('-v "$models:/models:ro"')&&probe.includes('RSRS_M3_DIR=/profile/models/bge-m3'),'model installation must use an owned target and retain read-only host inputs');
 const text=readFileSync(new URL('../.github/workflows/token-free-sdk-check.yml',import.meta.url),'utf8').replace(/\r\n/g,'\n');
 const global=text.split('    env:')[1].split('    steps:')[0];assert(!global.includes('RSRS_CORE_TEST_MODE'));assert(text.includes('model install-m3'));assert(text.includes('model probe'));
 const program=text.split('CLI_FIXTURE_BINARY="$exe" node --input-type=module <<\'NODE\'\n')[1].split('          NODE')[0].replace(/^[ \t]*import .+;[ \t]*$/gm,'');
 assert.doesNotMatch(program,/readFileSync\('sdk\/core-sdk.lock.json'|core.sdk_version, sdk.sdk_version/);
 const target='x86_64-unknown-linux-gnu',runtime='/data/bin/runtime/2.0.0-dev.18/rsrs-runtime';
 const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
 const check=(change=()=>{})=>{
  const core={schema_version:1,target,sdk_version:'2.0.0-dev.3'};
  const metadata={schema_version:2,source_commit:'a'.repeat(40),triple:target,runtime_version:'2.0.0-dev.18',binary_sha256:hash('Runtime bytes'),files:[]};
  const selected={version:metadata.runtime_version,sha256:metadata.binary_sha256,release:{}};
  const files=new Map([[runtime,Buffer.from('Runtime bytes')]]);
  const seal=()=>{
   const bytes=Buffer.from(JSON.stringify(core));files.set('/data/bin/runtime/2.0.0-dev.18/core-runtime.json',bytes);
   metadata.files=[{path:'core-runtime.json',sha256:hash(bytes)}];
   selected.release.metadata_json=JSON.stringify(metadata);selected.release.metadata_sha256=hash(selected.release.metadata_json);
  };
  seal();change({core,metadata,selected,files,seal});
  files.set('/data/bin/runtime.json',JSON.stringify(selected));files.set('runtime-pin.json',JSON.stringify({required:metadata.runtime_version}));
  const output=[];
  runInNewContext(program,{assert,createHash,join:posix.join,dirname:posix.dirname,
   readFileSync:name=>{assert(files.has(name),`Unexpected input ${name}`);return files.get(name);},
   realpathSync:name=>name,statSync:()=>({isFile:()=>true}),appendFileSync:(file,value)=>output.push(value),
   spawnSync:(command,args)=>{assert.equal(command,'bash');assert.equal(args[0],'scripts/probe-native-arm64-alpine.sh');return {status:0};},
   process:{platform:'linux',env:{RSRS_DATA_DIR:'/data',SDK_TARGET:target,RSRS_RUNTIME_TRIPLE:target,CLI_FIXTURE_BINARY:'/cli',GITHUB_ENV:'/env',RUNNER_TEMP:'/temp',RSRS_M3_DIR:'/model'}}});
  assert.deepEqual(output,[`RSRS_RUNTIME_BIN=${runtime}\n`]);
 };
 check();
 for(const change of [
  ({files})=>files.set(runtime,Buffer.from('changed Runtime bytes')),
  ({files})=>files.set('/data/bin/runtime/2.0.0-dev.18/core-runtime.json',Buffer.from('changed manifest')),
  ({selected})=>{selected.release.metadata_json+=' ';},
  ({core,seal})=>{core.sdk_version='';seal();},
  ({core,seal})=>{core.target='other-target';seal();},
  ({core,seal})=>{core.schema_version=2;seal();},
  ({metadata,seal})=>{metadata.source_commit='unverified';seal();},
 ])assert.throws(()=>check(change));
});

test('trusted producer refuses pre-existing SDK directory before any credential request',()=>{
 const dir=mkdtempSync(join(tmpdir(),'sdk-fresh-producer-'));
 try{
  mkdirSync(join(dir,'.sdk',TARGETS[0]),{recursive:true});
  const result=spawnSync(process.execPath,[fileURLToPath(new URL('./sdk-ci-cache.mjs',import.meta.url)),'prepare',TARGETS[0],JSON.stringify(lock().targets[TARGETS[0]])],{cwd:dir,encoding:'utf8',env:{PATH:process.env.PATH,GITHUB_REPOSITORY:'risense-ai/respire-cli',GITHUB_REF:'refs/heads/main',GITHUB_EVENT_NAME:'workflow_dispatch'}});
  assert.notEqual(result.status,0);assert.match(result.stderr,/requires a fresh SDK directory/);
 }finally{rmSync(dir,{recursive:true});}
});
test('cache tokens cap selected-source jobs at read and credential producer at write-only',()=>{
 const warm=readFileSync(new URL('../.github/workflows/private-sdk-cache.yml',import.meta.url),'utf8').replace(/\r\n/g,'\n');
 const plan=warm.split('\n  plan:\n')[1].split('\n  download:\n')[0],producer=warm.split('\n  download:\n')[1].split('\n  native:\n')[0],caller=warm.split('\n  native:\n')[1];
 assert.match(plan,/cache-mode: none/);assert.match(producer,/cache-mode: write-only/);assert.match(producer,/package-manager-cache: false/);assert(!/cache\/restore|uses: actions\/cache@/.test(producer));assert.match(producer,/cache\/save@v4/);assert.match(caller,/cache-mode: read/);
 const reusable=readFileSync(new URL('../.github/workflows/token-free-sdk-check.yml',import.meta.url),'utf8').replace(/\r\n/g,'\n');assert.match(reusable,/native-source:\n    cache-mode: read/);
 for(const file of ['ci.yml','release-validation.yml','accelerator.yml']){const text=readFileSync(new URL('../.github/workflows/'+file,import.meta.url),'utf8').replace(/\r\n/g,'\n');assert.match(text,/^cache-mode: read$/m);const consumers=text.replace(/\n  rust-build-save:\n[\s\S]*?(?=\n  [a-z][\w-]*:\n)/g,'');assert(!/uses: actions\/cache(?:@|\/save)/.test(consumers));}
});
test('every SDK cache consumer rejects primary-key prefix matches before source execution',()=>{
 for(const file of ['ci.yml','release-validation.yml','accelerator.yml','token-free-sdk-check.yml']){
  const text=readFileSync(new URL('../.github/workflows/'+file,import.meta.url),'utf8').replace(/\r\n/g,'\n');
  for(const match of text.matchAll(/      - uses: actions\/cache\/restore@v4\n([\s\S]*?)(?=      - (?:name:|uses:))/g)){
   if(!match[1].includes('path: .sdk/'))continue;
   const id=match[1].match(/id: ([a-z0-9-]+)/)[1],following=text.slice(match.index+match[0].length).split(/\n      - (?:name:|uses:)/)[0];
   assert(following.includes('steps.'+id+'.outputs.cache-matched-key'));
   const run=following.match(/test -n "\$EXPECTED_KEY" && test "\$MATCHED_KEY" = "\$EXPECTED_KEY"|test -n "\$EXPECTED_KEY" && test "\$EXPECTED_KEY" = "\$MATCHED_KEY"/)?.[0];
   assert(run,'SDK cache identity must have an executable exact-key guard');
   for(const [matched,status] of [['expected',0],['expected-suffix',1],['',1]]){
    const result=spawnSync('bash',['-c',run],{encoding:'utf8',env:{EXPECTED_KEY:'expected',MATCHED_KEY:matched}});assert.equal(result.status,status);
   }
  }
 }
});

for (const version of ['1.0.2-dev.24','1.1.0-dev.1','2.0.0-dev.1']) {
 test(`approved SDK train ${version} keeps canonical target identities`,()=>{
  const input=lock(version),plan=planCaches(input,structuredClone(input));
  assert.equal(plan.include.length,TARGETS.length);
  assert(plan.include.every(item=>item.entry.sdk_version===version));
  assert.notEqual(cacheKey(TARGETS[0],input.targets[TARGETS[0]]),cacheKey(TARGETS[0],lock().targets[TARGETS[0]]));
 });
}
for (const version of ['1.1.0','1.1.0-dev.0','1.1.0-dev.01','1.1.0-rc.1','1.1.0-dev.1+metadata','1.1.1-dev.1']) {
 test(`SDK cache rejects unsupported version ${version}`,()=>assert.throws(()=>planCaches(lock(version),lock(version)),/tag\/version/));
}
