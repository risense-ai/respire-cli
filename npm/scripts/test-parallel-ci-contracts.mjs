import test from 'node:test';
import assert from 'node:assert/strict';
import {existsSync,readFileSync,readdirSync,mkdtempSync,mkdirSync,writeFileSync,utimesSync,statSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {execFileSync} from 'node:child_process';
import {runInNewContext} from 'node:vm';
import {createHash} from 'node:crypto';
import {cacheKey,releaseKey} from '../../scripts/rust-ci-cache.mjs';
const ci=readFileSync(new URL('../../.github/workflows/ci.yml',import.meta.url),'utf8').replace(/\r\n/g,'\n');
const section=name=>ci.split(`\n  ${name}:\n`)[1]?.split(/\n  [a-z][\w-]*:\n/)[0];
test('independent contract checks do not wait for Rust coverage or receive SDK/publish credentials',async()=>{
  const contracts=section('contract-checks'),source=section('coverage-tests'),workspace=section('workspace-tests'),integration=section('runtime-integration');
  assert(contracts && source);assert.doesNotMatch(contracts,/\n    needs:|id-token:|actions: write|secrets\.|fetch-core-sdk|cargo /);
  assert.match(contracts,/persist-credentials: false/);assert.match(contracts,/contents: read/);
  assert.match(workspace,/cargo test --locked -p respire_spawn -p respire_protocol -p respire_client_host -p respire_commands -p respire_logging/);assert.doesNotMatch(source,/cargo test --workspace --exclude respire/);assert.doesNotMatch(workspace,/llvm-cov|needs:|fetch-core-sdk|path: \.sdk\//);assert.match(workspace,/RSRS_CORE_TEST_MODE: '1'/);
  assert(workspace.indexOf('cargo test --locked -p respire_spawn')<workspace.indexOf('python3 scripts/test-core-payload-lifetime.py'));assert(workspace.includes('python3 scripts/test-core-payload-lifetime.py'));assert.doesNotMatch(contracts,/test-core-payload-lifetime.py/);assert(workspace.includes('python3 scripts/test-ci-source-profile.py'));
  assert.match(source,/group: \[core, runtime_smoke, runtime_autostart\]/);
  assert.match(source,/fail-fast: false/);assert.match(source,/RSRS_CORE_TEST_MODE: '1'/);
  assert.match(source,/targets.filter\(t => t.kind.includes\('test'\)\)/);
  assert.match(source,/tests.filter\(name => !isolated.includes\(name\)\)/);
  assert.match(source,/args.push\('--lib', '--bins', '--examples'\)/);
  assert.match(source,/if \(process.env.CANDIDATE_MODE !== 'true' \|\| group === 'runtime_autostart'\) process.exit\(status\)/);
  assert.match(source,/process.exit\(status !== 0 \? status : \(result.status \?\? 1\)\)/);
  const business=readFileSync(new URL('../../scripts/run-runtime-business-tests.sh',import.meta.url),'utf8').replace(/\r\n/g,'\n');
  assert.match(business,/^set -euo pipefail$/m);
  assert(business.includes('coverage_dir="$PWD/target/llvm-cov-target"'));
  assert(business.includes('CARGO_LLVM_COV_TARGET_DIR="$coverage_dir" cargo llvm-cov show-env --sh'));
  assert(business.includes('source "$RUNNER_TEMP/cli-coverage.env"'));
  assert(business.includes('if [[ "${RUSTFLAGS:-}${CARGO_ENCODED_RUSTFLAGS:-}" != *instrument-coverage* ]]; then'));
  assert(business.includes('if [[ "${__CARGO_LLVM_COV_RUSTC_WRAPPER:-}" != 1 || -z "${RUSTC_WRAPPER:-}" || "${__CARGO_LLVM_COV_RUSTC_WRAPPER_RUSTFLAGS:-}" != *instrument-coverage* ]]; then'));
  assert(business.includes('if [[ "${LLVM_PROFILE_FILE:-}" != "$coverage_dir/"* ]]; then'));
  assert.equal((business.match(/^ {2,4}exit 1$/gm)||[]).length,2,'instrumentation and profile guards must fail closed');
  for(const binding of ['export RSRS_CLI_BIN="$coverage_dir/debug/rsrs"','export RSRS_CLI_SOURCE_DIR="$PWD"',
    'export RSRS_CLI_SOURCE_SHA="$(git rev-parse HEAD)"','test -x "$RSRS_CLI_BIN"'])assert(business.includes(binding),binding);
  const before='original_cli="$(sha256sum "$RSRS_CLI_BIN")"',after='test "$(sha256sum "$RSRS_CLI_BIN")" = "$original_cli"';
  const invoke='"$RSRS_RUNTIME_TEST_RUNNER" "$module::" --test-threads=1';
  assert(business.indexOf(before)>=0&&business.indexOf(before)<business.indexOf(invoke));
  assert(business.indexOf(after)>business.indexOf(invoke),'the same instrumented CLI must retain its hash');
  assert(business.includes('for module in $RUNTIME_BUSINESS_MODULES; do'));
  assert(business.includes('if [[ "$business_status" == 0 && "$module_status" != 0 ]]; then business_status=$module_status; fi'),
    'run every module and preserve the first failure');
  assert(business.includes('if [[ "${RUNTIME_REQUIRE_NATIVE_STOP:-0}" == 1 && "$module" == diary_identity ]]; then'));
  assert(business.includes(`${invoke} --show-output > "$native_log" 2>&1`));
  assert.doesNotMatch(business,/tee|cat "\$native_log"|--nocapture/);
  assert(business.includes('native_log="$(mktemp "$RUNNER_TEMP/native-stop-private.XXXXXX")"'));
  assert(business.includes('"$native_seen" != 1'),'required native case cannot silently be omitted');
  assert(business.trimEnd().endsWith(`${after}\nexit "$business_status"`),
    'verify the unchanged CLI before returning the retained business status');
  assert(business.indexOf('unset GH_TOKEN GITHUB_TOKEN')>business.indexOf(before));
  assert(business.indexOf('unset GH_TOKEN GITHUB_TOKEN')<business.indexOf(invoke));
  assert.doesNotMatch(business,/cargo\s+(?:build|test|run|metadata)\b|cargo\s+llvm-cov\s+(?:run|test)\b/);
  const evidenceProgram=business.split("<<'NODE'\n")[1].split('\nNODE')[0].replace(/^import .+;$/gm,'');
  const sha='a'.repeat(40),harnessSha='b'.repeat(40),productSha='c'.repeat(40);
  const hashNative=bytes=>createHash('sha256').update(bytes).digest('hex');
  const runtimeBytes=Buffer.from('synthetic pinned Runtime');
  const metadataNative=JSON.stringify({schema_version:2,runtime_version:'synthetic',source_commit:productSha,binary_sha256:hashNative(runtimeBytes)});
  const receiptNative={sha256:hashNative(runtimeBytes),release:{metadata_json:metadataNative,metadata_sha256:hashNative(metadataNative)}};
  const prefixNative=['start','fixture_ready','memory_seeded','runtime_ready','provider_received','active_verified','stop_accepted'];
  const suffixNative=['same_key_checked','business_completed','runtime_stopped','store_unchanged','restarted','stale_rejected','restart_stopped','complete'];
  const checkpointsNative=['normal','forced'].flatMap(mode=>[...prefixNative,...(mode==='normal'?['normal_waited']:['force_identities_rejected','worker_reaped']),...suffixNative]
    .map(stage=>`NATIVE_STOP_CHECKPOINT mode=${mode} stage=${stage}`));
  const testlineNative='test diary_identity::native_stop_waits_and_explicit_force_reaps_real_core_without_replay ... ok';
  const completeNative=[testlineNative,...checkpointsNative,'NATIVE_STOP_RAW synthetic-private-marker','synthetic-secret-canary'].join('\n');
  const runEvidence=(output,status='0',mutate={})=>{
    const printed=[],exits=[];
    const files={'runtime-tests-source.json':JSON.stringify({source_sha:harnessSha}),
      'runtime-pin.json':JSON.stringify({required:'synthetic'}),'/runtime.json':JSON.stringify(receiptNative),
      '/runtime/version/rsrs-runtime':runtimeBytes,'/private-log':output,'/cli':'CLI bytes','/harness':'harness bytes',...mutate};
    runInNewContext(evidenceProgram,{assert,createHash,dirname:path.posix.dirname,join:path.posix.join,
      realpathSync:value=>value,readFileSync:name=>{assert(Object.hasOwn(files,name),name);return files[name];},
      execFileSync:(command,args)=>{assert.equal(command,'git');return args[1]==='.'?sha:harnessSha;},
      console:{log:line=>printed.push(line)},process:{argv:['node','-','/private-log',status],
        env:{RSRS_CLI_SOURCE_SHA:sha,GITHUB_SHA:sha,GITHUB_RUN_ID:'123',GITHUB_RUN_ATTEMPT:'1',
          RSRS_RUNTIME_BIN:'/runtime/version/rsrs-runtime',EXPECTED_RUNTIME_PRODUCT_SOURCE_SHA:productSha,
          RSRS_CLI_BIN:'/cli',RSRS_RUNTIME_TEST_RUNNER:'/harness'},exit:code=>exits.push(code)}});
    assert.equal(printed.length,1);assert.doesNotMatch(printed[0],/synthetic-secret|synthetic-private|private-log/);
    return {report:JSON.parse(printed[0]),exits};
  };
  assert.equal(runEvidence(completeNative).report.passed,true);
  assert.equal(runEvidence(completeNative).report.runtime_tests_source_sha,harnessSha);
  assert.equal(runEvidence(completeNative).report.runtime_product_source_sha,productSha);
  assert.equal(runEvidence(completeNative).report.runtime_version,'synthetic');
  assert.deepEqual(runEvidence(completeNative).exits,[]);
  const diagnostic = runEvidence(completeNative).report.safe_native_diagnostic;
  assert.equal(diagnostic.checkpoint_modes.normal.last_stage,'complete');
  assert.equal(diagnostic.checkpoint_modes.normal.valid_count,16);
  assert.equal(diagnostic.checkpoint_modes.forced.last_stage,'complete');
  assert.equal(diagnostic.checkpoint_modes.forced.valid_count,17);
  assert.equal(diagnostic.native_failure_kind,null);
  const forcedPrefix=checkpointsNative.slice(0,16+7).join('\n');
  const failureBlock=[`---- diary_identity::native_stop_waits_and_explicit_force_reaps_real_core_without_replay stdout ----`,
    `thread 'diary_identity::native_stop_waits_and_explicit_force_reaps_real_core_without_replay' panicked at /synthetic-secret/location/diary_identity.rs:1812:7:`,
    'synthetic-secret panic body', '---- diary_identity::unrelated stdout ----',
    `thread 'diary_identity::native_stop_waits_and_explicit_force_reaps_real_core_without_replay' panicked at /private-log/diary_identity.rs:999:2:`].join('\n');
  const failedDiagnostic=runEvidence(forcedPrefix+'\n'+failureBlock,'101').report.safe_native_diagnostic;
  assert.equal(failedDiagnostic.checkpoint_modes.normal.last_stage,'complete');
  assert.equal(failedDiagnostic.checkpoint_modes.forced.last_stage,'stop_accepted');
  assert.equal(failedDiagnostic.checkpoint_modes.forced.stages_seen.force_identities_rejected,false);
  assert.equal(failedDiagnostic.native_failure_kind,'native_panic');
  assert.deepEqual(failedDiagnostic.native_failure_locations,[{file:'diary_identity.rs',line:1812,column:7}]);
  const rust195=failureBlock.replace("' panicked at ","' (1842) panicked at ");
  assert.deepEqual(runEvidence(rust195,'101').report.safe_native_diagnostic.native_failure_locations,
    [{file:'diary_identity.rs',line:1812,column:7}]);
  for(const invalidThreadId of ['-1','synthetic-secret-canary','12345678901']) {
    const output=failureBlock.replace("' panicked at ",`' (${invalidThreadId}) panicked at `);
    const report=runEvidence(output,'101').report.safe_native_diagnostic;
    assert.deepEqual(report.native_failure_locations,[]);
    assert.equal(report.native_failure_kind,'native_failure_unlocated');
  }

  for(const invalidLocation of ['0:1','20001:1','1:0','1:4097']) {
    const output=failureBlock.replace('1812:7',invalidLocation);
    assert.deepEqual(runEvidence(output,'101').report.safe_native_diagnostic.native_failure_locations,[]);
  }
  const unknownDiagnostic=runEvidence(forcedPrefix+'\nNATIVE_STOP_CHECKPOINT mode=forced stage=synthetic-secret-canary','101').report.safe_native_diagnostic;
  assert.equal(unknownDiagnostic.unknown_checkpoint_count,1);
  assert.equal(unknownDiagnostic.checkpoint_modes.forced.last_stage,'stop_accepted');
  const capped=runEvidence(checkpointsNative.concat(Array(100).fill(checkpointsNative[0])).join('\n'),'101').report.safe_native_diagnostic;
  assert.equal(capped.checkpoint_modes.normal.valid_count,64);assert.equal(capped.checkpoint_modes.normal.count_capped,true);
  const resultError=runEvidence('---- diary_identity::native_stop_waits_and_explicit_force_reaps_real_core_without_replay stdout ----\nError: synthetic-secret-canary','101').report.safe_native_diagnostic;
  assert.equal(resultError.native_failure_kind,'native_result_error');
  const nativeHeader='---- diary_identity::native_stop_waits_and_explicit_force_reaps_real_core_without_replay stdout ----';
  const blockCapped=runEvidence(nativeHeader+'\n'+Array(4097).fill('synthetic-secret-canary').join('\n'),'101').report.safe_native_diagnostic;
  assert.equal(blockCapped.native_block_capped,true);
  const panicPrefix="thread 'diary_identity::native_stop_waits_and_explicit_force_reaps_real_core_without_replay' panicked at ";
  const manyLocations=runEvidence(nativeHeader+'\n'+[1,2,3,4,5].map(line=>panicPrefix+`/synthetic-secret/diary_identity.rs:${line}:1:`).join('\n'),'101').report.safe_native_diagnostic;
  assert.equal(manyLocations.native_failure_locations.length,4);

  for(const [output,status] of [[completeNative.replace(testlineNative,''),'0'],
    [completeNative.replace('mode=normal stage=normal_waited','mode=normal stage=invalid'),'0'],
    [completeNative.replace('mode=forced stage=worker_reaped','mode=forced stage=invalid'),'0'],
    [completeNative+'\n'+checkpointsNative[0],'0'],[completeNative+'\nNATIVE_STOP_CHECKPOINT mode=unknown stage=start','0'],
    [completeNative,'17']]){
    const result=runEvidence(output,status);assert.equal(result.report.passed,false);assert.deepEqual(result.exits,[1]);
  }
  assert.throws(()=>runEvidence(completeNative,'0',{'runtime-tests-source.json':JSON.stringify({source_sha:sha})}));
  assert.throws(()=>runEvidence(completeNative,'0',{'/runtime/version/rsrs-runtime':Buffer.from('changed bytes')}));
  const imports=new Set(["import assert from 'node:assert/strict';",
    "import {execFileSync, spawnSync} from 'node:child_process';",
    "import {readFileSync} from 'node:fs';",
    "import {captureCoverage} from './scripts/produce-required-tests.mjs';"]);
  const blocks=source.split("node --input-type=module <<'NODE'\n").slice(1)
    .map(block=>block.split('\n          NODE')[0]).filter(block=>block.includes("const metadata = JSON.parse(execFileSync('cargo'"));
  assert.equal(blocks.length,1,'coverage selection must have one executable source block');
  const program=blocks[0].replace(/^[ \t]*import .+;[ \t]*$/gm,statement=>{
    assert(imports.has(statement.trim()),`inject the coverage dependency explicitly: ${statement.trim()}`);
    return '';
  });
  assert.doesNotMatch(program,/^[ \t]*import\b/m);
  // This CLI uses Cargo's automatic integration-test discovery; keep this guard product-free.
  const manifest=readFileSync(new URL('../../cli/Cargo.toml',import.meta.url),'utf8');
  assert.doesNotMatch(manifest,/^\s*(?:autotests\s*=\s*false|\[\[test\]\])/m);
  const allTests=readdirSync(new URL('../../cli/tests/',import.meta.url),{withFileTypes:true})
    .flatMap(entry=>entry.isFile()&&entry.name.endsWith('.rs')?[entry.name.slice(0,-3)]:
      entry.isDirectory()&&existsSync(new URL(`../../cli/tests/${entry.name}/main.rs`,import.meta.url))?[entry.name]:[]);
  const metadata={packages:[{name:'respire',targets:allTests.map(name=>({name,kind:['test']}))}]};
  const runner='runtime-business-test-runner';
  const listing=Object.entries({memory_revision:6,diary_identity:12,snapshot_lifecycle:8,account:3,capture_main:2})
    .flatMap(([module,count])=>Array.from({length:count},(_,i)=>`${module}::${module==='diary_identity'&&i===11?'native_stop_waits_and_explicit_force_reaps_real_core_without_replay':`case_${i}`}: test`)).join('\n');
  const selected=[];
  for(const group of ['core','runtime_smoke','runtime_autostart'])for(const originalStatus of [0,23])for(const businessStatus of [0,17,null]){
    const calls=[],harness=[],exits=[],raw=[],listed=[];
    assert.throws(()=>runInNewContext(program,{
      assert,readFileSync,
      execFileSync:(command,args)=>{
        if(command==='cargo'){assert.deepEqual(Array.from(args),['metadata','--locked','--no-deps','--format-version','1']);return JSON.stringify(metadata);}
        assert.equal(command,runner);assert.deepEqual(Array.from(args),['--list']);listed.push(command);return listing;
      },
      spawnSync:(command,args,options)=>{
        if(command==='cargo'){calls.push(args);return {status:originalStatus};}
        assert.equal(options.stdio,'inherit');
        assert.equal(options.env.GH_TOKEN,'synthetic-gh');assert.equal(options.env.GITHUB_TOKEN,'synthetic-github');
        if(group==='runtime_smoke'){
          assert.equal(command,'env');
          assert.deepEqual(Array.from(args),['-u','DBUS_SESSION_BUS_ADDRESS','-u','DBUS_SESSION_BUS_PID',
            '-u','DBUS_STARTER_ADDRESS','-u','DBUS_STARTER_BUS_TYPE','-u','GNOME_KEYRING_CONTROL',
            '-u','GNOME_KEYRING_PID','-u','SSH_AUTH_SOCK','dbus-run-session','--','env','RSRS_SS_FIXTURE_BUS=private',
            'python','-B','scripts/dev-secret-service-keyring-selftest.py','--root',
            '/synthetic-runner/account-private-secret-service','--','bash','scripts/run-runtime-business-tests.sh']);
        }else{
          assert.equal(command,'bash');assert.deepEqual(Array.from(args),['scripts/run-runtime-business-tests.sh']);
        }
        assert.equal(options.env.RUNTIME_REQUIRE_NATIVE_STOP,group==='core'?'1':'0');
        harness.push(options.env.RUNTIME_BUSINESS_MODULES);
        return {status:businessStatus};
      },
      captureCoverage:args=>{calls.push(args);raw.push(originalStatus);return originalStatus;},
      process:{env:{CANDIDATE_MODE:'true',COVERAGE_GROUP:group,RSRS_RUNTIME_TEST_RUNNER:runner,RUNNER_TEMP:'/synthetic-runner',
        GH_TOKEN:'synthetic-gh',GITHUB_TOKEN:'synthetic-github'},exit:status=>{exits.push(status);throw exits;}},
    }),error=>error===exits);
    assert.deepEqual(exits,[originalStatus!==0?originalStatus:group==='runtime_autostart'?0:(businessStatus??1)]);
    assert.equal(calls.length,1);assert.deepEqual(raw,group==='core'?[originalStatus]:[]);
    assert.equal(listed.length,group==='runtime_autostart'?0:1);
    assert.deepEqual(harness,group==='runtime_autostart'?[]:[group==='core'?'memory_revision diary_identity snapshot_lifecycle capture_main':'account']);
    if(originalStatus===0&&businessStatus===0)for(let i=0;i<calls[0].length;i++)if(calls[0][i]==='--test')selected.push(calls[0][i+1]);
    if(group==='core')for(const flag of ['--lib','--bins','--examples'])assert(calls[0].includes(flag));
  }
  assert.deepEqual(selected.sort(),allTests.sort(),'every integration target must run exactly once');
  // Source mode runs the same CLI selection but must never dispatch a Runtime harness.
  for(const group of ['core','runtime_smoke','runtime_autostart'])for(const status of [0,23]){
    const exits=[],calls=[];
    assert.throws(()=>runInNewContext(program,{
      assert,
      execFileSync:(command,args)=>{assert.equal(command,'cargo');return JSON.stringify(metadata);},
      spawnSync:(command,args)=>{assert.equal(command,'cargo');calls.push(args);return {status};},
      captureCoverage:args=>{calls.push(args);return status;},
      process:{env:{CANDIDATE_MODE:'false',COVERAGE_GROUP:group},exit:value=>{exits.push(value);throw exits;}},
    }),error=>error===exits);
    assert.deepEqual(exits,[status]);assert.equal(calls.length,1);
  }
  assert.match(workspace,/cargo test --locked -p respire_spawn -p respire_protocol -p respire_client_host -p respire_commands/);
  for(const lane of [workspace,source]){
    assert.match(lane,/CANDIDATE_MODE: \$\{\{ inputs.required_candidate_run_id/);
    assert.doesNotMatch(lane,/fetch-core-sdk|path: \.sdk\/|sdk-cache-2/);
  }
  assert.match(source,/name: Coverage \(\$\{\{ matrix.group \}\}\)/);
  for(const name of ['Prepare private business credential fixture','Resolve exact Runtime business test source',
    'Bind Runtime business harness and SDK identity','Verify or install the real business test model using the official installer',
    'Verify precompiled Runtime business assertions without instrumenting Runtime']){
    const block=source.split(`- name: ${name}\n`)[1]?.split('\n      - ')[0];
    assert(block?.includes("if: env.CANDIDATE_MODE == 'true'"),name);
  }
  const registry=JSON.parse(readFileSync(new URL('../../scripts/required-tests.json',import.meta.url),'utf8'));
  for(const item of registry.tests.filter(item=>item.evidence?.job==='coverage-tests')){
    assert.equal(item.evidence.job_name,'Coverage (core)');assert(source.includes(item.evidence.command_fragment));
  }
  assert.match(integration,/needs: coverage-tests/);
  assert.match(integration,/node scripts\/fetch-runtime-test-bundle\.mjs source/);
  assert.match(integration,/ref: \$\{\{ steps.runtime-tests.outputs.sha \}\}/);
  assert.match(integration,/channel\(pinVersion\), channel\(cliVersion\)/);
  assert.match(integration,/tar --exclude='\*\.profraw' -xzf/);
  assert.match(integration,/INTEGRATION_CLI_SHA256/);
  assert.match(integration,/source_archive_sha256/);
  for(const lane of [source,integration])assert.match(lane,/tar --hard-dereference -cf - -T "\$RUNNER_TEMP\/coverage-files" \| gzip -1/);
  assert.match(integration,/runtime_tests_sha: env.RUNTIME_TESTS_SHA/);
  assert.match(integration,/Preserve private business credential diagnostics\n        if: \$\{\{ always\(\)/);
  assert.match(integration,/steps.business.outcome == 'failure'/);
  assert.match(integration,/cargo test --locked -p respire_spawn -p respire_protocol -p respire_client_host -p respire_commands -p respire_logging/);
  for(const lane of [workspace,source,integration])assert.doesNotMatch(lane,/--workspace|--manifest-path \.runtime-examples|stage-core-runtime\.mjs|fetch-core-sdk/);
  for(const lane of [source,integration]){
    assert.match(lane,/node scripts\/fetch-runtime-test-bundle\.mjs fetch "\$target"/);
    assert.match(lane,/node scripts\/fetch-runtime-test-bundle\.mjs verify "\$target" --list/);
  }
  assert.match(integration,/python3 scripts\/test-core-payload-lifetime.py/);
  const jointBlock=integration.split("      - name: Run Runtime business assertions against the source CLI")[1].split("      - name: Preserve private business credential diagnostics")[0];
  const jointProgram=jointBlock.split("node --input-type=module <<'NODE'\n")[1].split('          NODE')[0]
    .replace(/^[ \t]*import .+;[ \t]*$/gm,'');
  assert.equal(jointProgram.slice(jointProgram.indexOf('const runner =')).trim(),
    program.slice(program.indexOf('const runner =')).trim()
      .replace('process.exit(status !== 0 ? status : (result.status ?? 1));','process.exit(result.status ?? 1);'),
    'source integration must reuse the original candidate business dispatch');
  for(const group of ['core','runtime_smoke'])for(const status of [0,17,null]){
    const exits=[],modules=[];
    assert.throws(()=>runInNewContext(jointProgram,{
      assert,
      execFileSync:(command,args)=>{assert.equal(command,runner);assert.deepEqual(Array.from(args),['--list']);return listing;},
      spawnSync:(command,args,options)=>{
        assert.equal(command,group==='core'?'bash':'env');
        if(group==='runtime_smoke')assert(Array.from(args).includes('RSRS_SS_FIXTURE_BUS=private'));
        assert.equal(options.env.RUNTIME_REQUIRE_NATIVE_STOP,group==='core'?'1':'0');
        modules.push(options.env.RUNTIME_BUSINESS_MODULES);return {status};
      },
      process:{env:{COVERAGE_GROUP:group,RSRS_RUNTIME_TEST_RUNNER:runner,RUNNER_TEMP:'/synthetic-runner'},
        exit:value=>{exits.push(value);throw exits;}},
    }),error=>error===exits);
    assert.deepEqual(exits,[status??1]);
    assert.deepEqual(modules,[group==='core'?'memory_revision diary_identity snapshot_lifecycle capture_main':'account']);
  }


  // Reject unallocated assertions before either dispatcher can execute a module.
  for(const dispatch of [program,jointProgram])for(const invalid of [
    `${listing}\nnew_module::unassigned: test`,
    listing.replace('native_stop_waits_and_explicit_force_reaps_real_core_without_replay','case_11'),
    listing.replace('account::case_0: test','account::case_1: test'),
    listing.replace('account::case_0: test','new_module::unassigned: test'),
  ]){
    assert.throws(()=>runInNewContext(dispatch,{
      assert,readFileSync,
      execFileSync:command=>command==='cargo'?JSON.stringify(metadata):invalid,
      spawnSync:command=>{assert.equal(command,'cargo','invalid inventory must not dispatch business modules');return {status:0};},
      captureCoverage:()=>0,
      process:{env:{CANDIDATE_MODE:'true',COVERAGE_GROUP:'core',RSRS_RUNTIME_TEST_RUNNER:runner},
        exit:()=>assert.fail('invalid inventory must fail before exit')},
    }),/Unassigned or duplicate|Missing migrated|Missing required native stop/);
  }
  const expectedProduct=ci.match(/^  EXPECTED_RUNTIME_PRODUCT_SOURCE_SHA: ([a-f0-9]{40})$/m)?.[1];
  assert.equal(expectedProduct,'a884395b585c3ce44f304f9004ccf72eeb76a99f');
  const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
  const binary=Buffer.from('synthetic official runtime'),cliBytes=Buffer.from('instrumented CLI'),archive=Buffer.from('source archive');
  const pinVersion=JSON.parse(readFileSync(new URL('../../runtime-pin.json',import.meta.url),'utf8')).required;
  const releaseMetadata={schema_version:2,runtime_version:pinVersion,source_commit:expectedProduct,binary_sha256:hash(binary)};
  const selection=()=>{const metadata_json=JSON.stringify(releaseMetadata);return {version:pinVersion,sha256:hash(binary),
    release:{metadata_json,metadata_sha256:hash(metadata_json)}};};
  const initialReceipt=group=>({schema:1,repository:'repo',source_sha:'cli-source',run_id:'123',run_attempt:'1',
    source_artifact:`coverage-${group}`,source_archive_sha256:hash(archive),cli_binary_sha256:hash(cliBytes),
    runtime_tests_sha:'b'.repeat(40),runtime_version:pinVersion});
  const productEnv={EXPECTED_RUNTIME_PRODUCT_SOURCE_SHA:expectedProduct,GITHUB_ACTIONS:'true',RUNTIME_FIXTURE_HOSTED:'true',
    RUNNER_TEMP:'/temp',GITHUB_ENV:'/env',GITHUB_OUTPUT:'/output',COVERAGE_GROUP:'core',GITHUB_REPOSITORY:'repo',
    GITHUB_SHA:'cli-source',GITHUB_RUN_ID:'123',GITHUB_RUN_ATTEMPT:'1'};
  const stripImports=block=>block.replace(/^[ \t]*import .+;[ \t]*$/gm,'');
  let boundReceipt;
  for(const lane of [source,integration]){
    const fixture=stripImports(lane.split('- name: Prepare official pinned standalone Runtime for lifecycle tests')[1]
      .split("node --input-type=module <<'NODE'\n")[1].split('          NODE')[0])
      .replace("const {installPinnedRuntime} = await import('./scripts/ci-install-pinned-runtime.mjs');",'');
    const runFixture=async(selected,actualBinary=binary)=>{
      let written;
      await runInNewContext(`(async()=>{${fixture}\n})()`,{assert,createHash,
        readFileSync:file=>file==='runtime-pin.json'?JSON.stringify({required:pinVersion}):file==='cli/Cargo.toml'?`version = "${pinVersion}"`:
          file.endsWith('/runtime.json')?JSON.stringify(selected):file.endsWith('.json')?JSON.stringify(initialReceipt('core')):actualBinary,
        mkdtempSync:()=>'/fixture',join:path.posix.join,resolve:file=>`/workspace/${file}`,realpathSync:file=>file,
        statSync:()=>({isFile:()=>true}),
        installPinnedRuntime:async(cli,{env},target)=>{
          assert.equal(cli,lane===source?'/workspace/target/debug/rsrs':'/workspace/target/llvm-cov-target/debug/rsrs');
          assert.equal(env.RSRS_DATA_DIR,'/fixture');assert.equal(target,'x86_64-unknown-linux-gnu');
          return {status:0};
        },appendFileSync:()=>{},
        writeFileSync:(file,value)=>{written=JSON.parse(value);},process:{env:productEnv}});
      return written;
    };
    const receipt=await runFixture(selection());
    if(lane===integration){boundReceipt=receipt;assert.equal(receipt.runtime_product_source_sha,expectedProduct);
      assert.equal(receipt.runtime_binary_sha256,hash(binary));assert.equal(receipt.runtime_metadata_sha256,hash(receipt.runtime_metadata_json));}
    for(const change of [
      value=>{const metadata=JSON.parse(value.release.metadata_json);metadata.source_commit='b'.repeat(40);
        value.release.metadata_json=JSON.stringify(metadata);value.release.metadata_sha256=hash(value.release.metadata_json);},
      value=>{value.release.metadata_sha256='0'.repeat(64);},
      value=>{value.sha256='0'.repeat(64);},
    ]){const value=selection();change(value);await assert.rejects(()=>runFixture(value));}
    await assert.rejects(()=>runFixture(selection(),Buffer.from('wrong binary')));
  }

  const report=section('check-complete');assert.match(report,/needs: \[coverage-tests, runtime-integration, workspace-tests, contract-checks, required-tests, commands-frontend\]/);
  assert.match(report,/for group in core runtime_smoke runtime_autostart/);
  assert.match(report,/coverage-integration-\$group.tar.gz/);
  assert.match(report,/receipt.source_archive_sha256/);
  const mergeProgram=stripImports(report.split("node --input-type=module <<'NODE'\n")[1].split('          NODE')[0]);
  const runMerge=receipt=>runInNewContext(mergeProgram,{assert,createHash,process:{env:productEnv},
    readFileSync:file=>file==='runtime-tests-source.json'?JSON.stringify({source_sha:'b'.repeat(40)}):
      file==='runtime-pin.json'?JSON.stringify({required:pinVersion}):file.endsWith('.json')?
        JSON.stringify({...receipt,source_artifact:`coverage-${file.includes('runtime_smoke')?'runtime_smoke':'core'}`}):archive,
    execFileSync:()=>cliBytes});
  runMerge(boundReceipt);
  for(const change of [
    value=>{value.runtime_product_source_sha='b'.repeat(40);},
    value=>{value.runtime_metadata_sha256='0'.repeat(64);},
    value=>{value.runtime_binary_sha256='0'.repeat(64);},
    value=>{const metadata=JSON.parse(value.runtime_metadata_json);metadata.source_commit='b'.repeat(40);
      value.runtime_metadata_json=JSON.stringify(metadata);value.runtime_metadata_sha256=hash(value.runtime_metadata_json);},
  ]){const receipt={...boundReceipt};change(receipt);assert.throws(()=>runMerge(receipt));}
  assert.match(report,/test \"\$INTEGRATION_RESULT\" = success/);
  assert.match(report,/node scripts\/check-cli-coverage\.mjs/);
  assert.match(report,/CANDIDATE_MODE: \$\{\{ inputs.required_candidate_run_id/);
  for(const script of ['test-publication-fence','test-publication-acceptance','test-cleanup-release-artifacts','test-registry-publication','test-release-publication','test-dev6-publication-recovery','test-parallel-publication']) {
    assert(contracts.includes(`npm/scripts/${script}.mjs`),script);assert(!source.includes(`npm/scripts/${script}.mjs`),`not serialized: ${script}`);
  }
  for(const script of ['test-private-sdk-download.mjs','test-sdk-ci-cache.mjs','test-stage-core-runtime.mjs','test-dev-smoke-gate.py','test-dev-api-contract.py','test-dev-model-fixture.py','test-dev-fixture-tty.py','test-dev-witness-fixture.py','test-reembed-progress-contract.ps1'])assert(contracts.includes(script),script);
  assert(readFileSync(new URL('../../scripts/test-dev-model-fixture.py',import.meta.url),'utf8').includes('from test_native_psutil_wheel_cache import NativePsutilWheelCacheTest'));
});
test('fail-closed aggregate separates source success from explicit candidate evidence',()=>{
  const complete=section('check-complete');assert.match(complete,/always\(\)/);assert.match(complete,/needs: \[coverage-tests, runtime-integration, workspace-tests, contract-checks, required-tests, commands-frontend\]/);
  assert.match(complete,/test "\$SOURCE_RESULT" = success && test "\$WORKSPACE_RESULT" = success && test "\$CONTRACT_RESULT" = success/);
  const requested="inputs.required_candidate_run_id != '' || inputs.required_candidate_artifact_id != '' || inputs.required_candidate_sha256 != ''";
  assert(section('required-tests').includes(`(${requested})`));
  assert(complete.includes('CANDIDATE_REQUESTED: ${{ '+requested+' }}'));
  const required=section('required-tests'),frontend=section('commands-frontend');
  const condition=block=>block.match(/    if: \$\{\{ (.+) \}\}/)[1];
  assert(required.includes('node scripts/verify-required-tests.mjs --ci'));
  assert.doesNotMatch(required,/allow-missing/);
  const validator=required.split("node --input-type=module <<'NODE'\n")[1].split('          NODE')[0].replace("          import assert from 'node:assert/strict';",'');
  const keys=['required_candidate_run_id','required_candidate_artifact_id','required_candidate_sha256'];
  const envKeys=['REQUIRED_CANDIDATE_RUN_ID','REQUIRED_CANDIDATE_ARTIFACT_ID','REQUIRED_CANDIDATE_SHA256'];
  for(let mask=1;mask<8;mask++)for(const mode of [null,'research_feedback_only','native_published_only','artifact_run','version_upgrade_only']){
    const values=['123','456','a'.repeat(64)].map((v,i)=>mask&(1<<i)?v:'');
    const inputs=Object.fromEntries([...keys.map((k,i)=>[k,values[i]]),...['research_feedback_only','native_published_only','version_upgrade_only'].map(k=>[k,k===mode]),['artifact_run',mode==='artifact_run'?'123':'']]);
    const context={inputs,always:()=>true};
    assert.equal(runInNewContext(condition(required),context),true,'any candidate input must run the verifier even in focused mode');
    assert.equal(runInNewContext(condition(complete),context),true,'candidate failures must reach the aggregate');
    assert.equal(runInNewContext(condition(frontend),context),true,'any candidate input must run commands frontend even in focused mode');
    const env={...Object.fromEntries(envKeys.map((k,i)=>[k,values[i]])),GITHUB_EVENT_NAME:'workflow_dispatch',FOCUSED_MODE:String(mode!==null)};
    const run=()=>runInNewContext(validator,{assert,process:{env}});
    if(mask===7&&mode===null)run();else assert.throws(run);
  }
  const absent={required_candidate_run_id:'',required_candidate_artifact_id:'',required_candidate_sha256:'',research_feedback_only:false,native_published_only:false,artifact_run:'',version_upgrade_only:false};
  assert.equal(runInNewContext(condition(required),{inputs:absent,always:()=>true}),false);
  assert.equal(runInNewContext(condition(complete),{inputs:absent,always:()=>true}),true);
  assert.equal(runInNewContext(condition(frontend),{inputs:absent}),true);
  for(const mode of ['research_feedback_only','native_published_only','artifact_run','version_upgrade_only']){
    assert.equal(runInNewContext(condition(complete),{inputs:{...absent,[mode]:mode==='artifact_run'?'123':true},always:()=>true}),false);
    assert.equal(runInNewContext(condition(frontend),{inputs:{...absent,[mode]:mode==='artifact_run'?'123':true}}),false);
  }
  for(const values of [['bad','456','a'.repeat(64)],['123','0','a'.repeat(64)],['123','456','bad']]){
    assert.throws(()=>runInNewContext(validator,{assert,process:{env:{...Object.fromEntries(envKeys.map((k,i)=>[k,values[i]])),GITHUB_EVENT_NAME:'workflow_dispatch',FOCUSED_MODE:'false'}}}));
  }
  const command=complete.split('        run: ').at(-1).trim();
  for(const candidate of ['true','false'])for(const source of ['success','failure','cancelled','skipped'])for(const required of ['success','failure','cancelled','skipped']){
    const result=execFileSync;
    let passed=true;
    try{result('bash',['-c',command],{env:{...process.env,SOURCE_RESULT:source,WORKSPACE_RESULT:'success',CONTRACT_RESULT:'success',COMMANDS_RESULT:'success',INTEGRATION_RESULT:candidate==='true'?'skipped':'success',REQUIRED_RESULT:required,CANDIDATE_REQUESTED:candidate},stdio:'pipe'});}catch{passed=false;}
    assert.equal(passed,source==='success'&&required===(candidate==='true'?'success':'skipped'),`${candidate}/${source}/${required}`);
  }
  for(const lane of ['WORKSPACE_RESULT','CONTRACT_RESULT','COMMANDS_RESULT','INTEGRATION_RESULT'])for(const status of ['failure','cancelled','skipped']){
    assert.throws(()=>execFileSync('bash',['-c',command],{env:{...process.env,SOURCE_RESULT:'success',WORKSPACE_RESULT:'success',CONTRACT_RESULT:'success',COMMANDS_RESULT:'success',INTEGRATION_RESULT:'success',REQUIRED_RESULT:'skipped',CANDIDATE_REQUESTED:'false',[lane]:status},stdio:'pipe'}));
  }
  assert.match(complete,/contents: read/);assert.match(complete,/actions: read/);assert.doesNotMatch(complete,/id-token:|actions: write|secrets\./);
  assert.match(complete,/SOURCE_RESULT: \$\{\{ needs.coverage-tests.result \}\}/);
  assert.match(complete,/REQUIRED_RESULT: \$\{\{ needs.required-tests.result \}\}/);
  for(const name of ['coverage-tests','check-complete','workspace-tests','contract-checks','commands-frontend'])assert.match(section(name),/!inputs.research_feedback_only && !inputs.native_published_only && !inputs.artifact_run && !inputs.version_upgrade_only/);
});


test('explicit manual source checks omit only the optional compile matrix and cannot replace Release push-CI proof',()=>{
  assert.match(ci,/source_checks_only:\n        description: Run all source tests, coverage and contracts/);
  assert.match(section('platform-build'),/!inputs.source_checks_only/);
  for(const name of ['workspace-tests','coverage-tests','contract-checks','check-complete'])assert.doesNotMatch(section(name),/!inputs.source_checks_only/);
  const release=readFileSync(new URL('../../.github/workflows/release.yml',import.meta.url),'utf8');
  assert.match(release,/run.head_sha===sha&&run.event==='push'/);
});


test('source metadata optimization retains debug safety and only the CLI test-stack exception',()=>{
  for(const name of ['workspace-tests','coverage-tests']){
    const text=section(name);
    for(const profile of ['DEV','TEST']){
      assert(text.includes(`CARGO_PROFILE_${profile}_DEBUG: line-tables-only`));
      assert(text.includes(`CARGO_PROFILE_${profile}_DEBUG_ASSERTIONS: 'true'`));
      assert(text.includes(`CARGO_PROFILE_${profile}_OVERFLOW_CHECKS: 'true'`));
      assert(text.includes(`CARGO_PROFILE_${profile}_OPT_LEVEL: '0'`));
    }
  }
  assert.match(section('check-complete'),/node scripts\/check-cli-coverage\.mjs/);
  assert.doesNotMatch(section('platform-build'),/CARGO_PROFILE_/);
  const manifest=readFileSync(new URL('../../Cargo.toml',import.meta.url),'utf8').replace(/\r\n/g,'\n');
  assert.match(manifest,/\[profile.dev.package.sha2\]\nopt-level = 3/);
  assert.doesNotMatch(manifest,/\[profile\.(?:dev|test)\]\n[^[]*opt-level\s*=\s*[1-3]/);
  // Clap's Windows debug builder exceeds 2 MiB; only this test package uses opt-level=1.
  // See docs/ci-source-profile.md for measured frames and default-stack validation.
  // The runtime split moved the clap derive into respire_commands, so both
  // test packages carry the stack guard.
  const assertProfiles=value=>assert.deepEqual(value.split(/(?=^\[)/m)
    .filter(block=>block.startsWith('[profile.'))
    .map(block=>block.split('\n').map(line=>line.trim()).filter(line=>line&&!line.startsWith('#')).join('\n')),[
      '[profile.dev.package.sha2]\nopt-level = 3',
      '[profile.release]\nstrip = "debuginfo"\nlto = false\ncodegen-units = 1\npanic = "unwind"',
      '[profile.test.package.respire]\nopt-level = 1',
      '[profile.test.package.respire_commands]\nopt-level = 1',
    ]);
  assertProfiles(manifest);
  for(const changed of [
    manifest.replace('[profile.test.package.respire]','[profile.dev.package.respire]'),
    manifest.replace('[profile.test.package.respire]\nopt-level = 1','[profile.test.package.respire]\nopt-level = 2'),
    manifest+'\n[profile.test.package.other]\nopt-level = 1\n',
    manifest+'\n[profile.test]\nopt-level = 1\n',
    manifest.replace('[profile.test.package.respire]','[profile.test.package.respire]\ndebug-assertions = false'),
    manifest.replace('panic = "unwind"','panic = "abort"'),
  ])assert.throws(()=>assertProfiles(changed));
  assert.deepEqual([...ci.matchAll(/^\s*RUST_MIN_STACK: (.+)$/gm)].map(match=>match[1]),
    ["'16777216'","'16777216'","'16777216'"],'the separated integration lane inherits the existing stack setting without raising it');
  const archive=section('coverage-tests');
  assert.match(archive,/set -euo pipefail/);
  assert.match(archive,/tar --hard-dereference -cf -[^\n]+\| gzip -1/);
  assert.match(archive,/compression-level: 0/);
  assert.match(archive,/cargo llvm-cov clean --profraw-only/);
  const identity={rust:'pinned compiler',locks:['dependencies','sdk'],flags:['coverage']};
  const key=cacheKey('coverage',identity);assert.match(key,/^rust-ci-v1-coverage-[a-f0-9]{64}$/);
  assert.equal(key,cacheKey('coverage',structuredClone(identity)));
  assert.notEqual(key,cacheKey('workspace',identity));
  for(const field of Object.keys(identity))assert.notEqual(key,cacheKey('coverage',{...identity,[field]:'changed'}));
  assert.throws(()=>cacheKey('sdk',identity));
  const releaseIdentity={...identity,target:'x86_64-unknown-linux-musl',container:'sha256:exact-container',sdk:'exact-sdk',profile:'release'};
  const releaseCacheKey=releaseKey(releaseIdentity.target,releaseIdentity);
  assert.match(releaseCacheKey,/^rust-release-v1-x86_64-unknown-linux-musl-[a-f0-9]{64}$/);
  assert.equal(releaseCacheKey,releaseKey(releaseIdentity.target,structuredClone(releaseIdentity)));
  for(const field of Object.keys(releaseIdentity))assert.notEqual(releaseCacheKey,releaseKey(releaseIdentity.target,{...releaseIdentity,[field]:'changed'}));
  assert.notEqual(releaseCacheKey,releaseKey('aarch64-unknown-linux-musl',releaseIdentity));
  assert.throws(()=>releaseKey('../other',releaseIdentity));
  const release=readFileSync(new URL('../../.github/workflows/release-validation.yml',import.meta.url),'utf8').replace(/\r\n/g,'\n');
  const binaries=release.split('\n  binaries:\n')[1].split('\n  native-regression:\n')[0];
  assert(binaries.indexOf('id: release-key')<binaries.indexOf('name: Prepare ephemeral build version'));
  assert.match(binaries,/key: \$\{\{ steps.release-key.outputs.key \}\}\n          enableCrossOsArchive: true/);
  const cachePack=binaries.split('      - name: Stage only release compilation dependencies')[1].split('      - uses: actions/upload-artifact@v4')[0];
  const cacheUpload=binaries.split('          name: release-dependency-cache-')[0].split('      - uses: actions/upload-artifact@v4').at(-1);
  assert.match(cachePack,/id: release-cache-pack/);assert.match(cachePack,/continue-on-error: true/);
  assert.match(cacheUpload,/continue-on-error: true/);assert.match(cacheUpload,/steps.release-cache-pack.outcome == 'success'/);
  for(const step of [cachePack,cacheUpload]){
    assert.match(step,/github.event_name == 'workflow_dispatch' \|\| github.event_name == 'push'/);
    assert.match(step,/github.ref == 'refs\/heads\/main'/);assert.match(step,/needs.resolve.outputs.sha == github.sha/);
  }
  assert.equal((binaries.match(/continue-on-error: true/g)||[]).length,2,'only optional cache maintenance may tolerate failure');
  assert.doesNotMatch(binaries,/restore-keys:|musl-\$\{\{ matrix.target \}\}-ort/);
  assert(binaries.indexOf('name: cli-release-')<binaries.indexOf('name: Stage only release compilation dependencies'));
  assert.match(binaries,/RELEASE_DEPENDENCY_CACHE: '1'/);
  assert.doesNotMatch(release,/\n  release-cache-save:|actions\/cache\/save/);
  assert.equal((binaries.match(/steps.release-cache.outputs.cache-hit != 'true'/g)||[]).length,2,'hot caches skip pack and artifact upload');
  const releaseWriter=readFileSync(new URL('../../.github/workflows/release-dependency-cache.yml',import.meta.url),'utf8').replace(/\r\n/g,'\n');
  assert.match(releaseWriter,/workflow_run:/);assert.match(releaseWriter,/types: \[completed\]/);
  assert.match(releaseWriter,/cache-mode: write-only/);
  assert.match(releaseWriter,/workflow_run.head_branch == 'main'/);
  assert.match(releaseWriter,/workflow_run.head_repository.full_name == github.repository/);
  assert.match(releaseWriter,/workflow_run.event == 'workflow_dispatch' \|\| github.event.workflow_run.event == 'push'/);
  assert.match(releaseWriter,/run\['event'\] not in \['workflow_dispatch','push'\]/);
  assert.match(releaseWriter,/enableCrossOsArchive: true/);
  assert.match(releaseWriter,/SOURCE_ATTEMPT/);assert.match(releaseWriter,/Foreign compilation cache source or attempt/);
  assert.match(releaseWriter,/if: needs.plan.outputs.available == 'true'/);
  assert.match(releaseWriter,/member.issym\(\).*member.islnk\(\)/);
  assert.match(releaseWriter,/filter='data'/);
  assert.doesNotMatch(releaseWriter,/actions\/checkout|secrets\.|cache\/restore|run: node|cargo /);
  const directory=mkdtempSync(path.join(tmpdir(),'rust-cache-timestamps-'));
  try {
    const cached=path.join(directory,'.rust-ci-cache/target/debug/deps/dependency.rlib');
    mkdirSync(path.dirname(cached),{recursive:true});writeFileSync(cached,'compiled dependency');
    const stamp=new Date('2001-01-01T00:00:00Z');utimesSync(cached,stamp,stamp);
    execFileSync(process.execPath,[fileURLToPath(new URL('../../scripts/rust-ci-cache.mjs',import.meta.url)),'restore','workspace'],{cwd:directory});
    const restored=path.join(directory,'target/debug/deps/dependency.rlib');
    assert.equal(readFileSync(restored,'utf8'),'compiled dependency');
    assert(Math.abs(statSync(restored).mtimeMs-stamp.getTime())<1,'Cargo dependency timestamps must survive restore');
    const target=execFileSync('rustc',['-Vv'],{encoding:'utf8'}).match(/^host: (.+)$/m)[1];
    const script=fileURLToPath(new URL('../../scripts/rust-ci-cache.mjs',import.meta.url));
    const virtual=path.join(directory,'virtual');mkdirSync(path.join(virtual,'member/src'),{recursive:true});
    const rootManifest='[workspace]\nmembers=["member"]\nresolver="2"\n[profile.release]\ncodegen-units=1\n';
    writeFileSync(path.join(virtual,'Cargo.toml'),rootManifest);
    writeFileSync(path.join(virtual,'member/Cargo.toml'),'[package]\nname="virtual_member"\nversion="0.1.0"\nedition="2021"\n');
    writeFileSync(path.join(virtual,'member/src/lib.rs'),'pub fn example() {}\n');
    writeFileSync(path.join(virtual,'Cargo.lock'),'version = 4\n[[package]]\nname = "virtual_member"\nversion = "0.1.0"\n');
    const keyEnv={...process.env,CARGO_HOME:path.join(virtual,'cargo-home'),GITHUB_OUTPUT:path.join(virtual,'output')};
    const virtualMetadata=JSON.parse(execFileSync('cargo',['metadata','--locked','--offline','--no-deps','--format-version','1'],{cwd:virtual,env:keyEnv,encoding:'utf8'}));
    assert(virtualMetadata.packages.every(pkg=>path.resolve(pkg.manifest_path)!==path.join(virtual,'Cargo.toml')));
    execFileSync(process.execPath,[script,'key','release',target],{cwd:virtual,env:keyEnv,stdio:'pipe'});
    const beforeRootProfileChange=readFileSync(path.join(virtual,'.rust-release-key'),'utf8');
    writeFileSync(path.join(virtual,'Cargo.toml'),rootManifest.replace('codegen-units=1','codegen-units=2'));
    execFileSync(process.execPath,[script,'key','release',target],{cwd:virtual,env:keyEnv,stdio:'pipe'});
    assert.notEqual(readFileSync(path.join(virtual,'.rust-release-key'),'utf8'),beforeRootProfileChange,'actual virtual-root release profile changes must invalidate the collected key');
    writeFileSync(path.join(directory,'Cargo.toml'),'[package]\nname="cache_fixture"\nversion="0.1.0"\nedition="2021"\n');
    writeFileSync(path.join(directory,'Cargo.lock'),'version = 4\n[[package]]\nname = "cache_fixture"\nversion = "0.1.0"\n');
    mkdirSync(path.join(directory,'src'));writeFileSync(path.join(directory,'src/main.rs'),'fn main() {}\n');
    // Let Cargo establish target ownership before restoring cached dependencies.
    execFileSync('cargo',['build','--release','--locked','--target',target,'--target-dir','target/ci'],{cwd:directory,stdio:'pipe'});
    assert(readFileSync(path.join(directory,'target/ci/CACHEDIR.TAG'),'utf8').startsWith('Signature: 8a477f597d28d172789f06886806bc55'));
    const key=releaseKey(target,releaseIdentity);
    writeFileSync(path.join(directory,'.rust-release-key'),key+'\n');
    mkdirSync(path.join(directory,'.rust-release-cache/target/release/deps'),{recursive:true});
    writeFileSync(path.join(directory,'.rust-release-cache/key'),key+'\n');
    const releaseDependency=path.join(directory,'.rust-release-cache/target/release/deps/dependency.rlib');
    writeFileSync(releaseDependency,'dependency-only');utimesSync(releaseDependency,stamp,stamp);
    execFileSync(process.execPath,[script,'restore','release',target],{cwd:directory});
    const releaseRestored=path.join(directory,'target/ci',target,'release/deps/dependency.rlib');
    assert.equal(readFileSync(releaseRestored,'utf8'),'dependency-only');
    assert(Math.abs(statSync(releaseRestored).mtimeMs-stamp.getTime())<1);
    writeFileSync(path.join(directory,'.rust-release-cache/key'),'wrong');
    assert.throws(()=>execFileSync(process.execPath,[script,'restore','release',target],{cwd:directory,stdio:'pipe'}));
    const cargoHome=path.join(directory,'cargo-home');
    mkdirSync(path.join(cargoHome,'registry/cache'),{recursive:true});
    writeFileSync(path.join(cargoHome,'credentials.toml'),'never-cache-this');
    const producer={...process.env,CARGO_HOME:cargoHome,GITHUB_SHA:'a'.repeat(40),GITHUB_RUN_ID:'123',GITHUB_RUN_ATTEMPT:'1'};
    execFileSync(process.execPath,[script,'pack','release',target],{cwd:directory,env:producer,stdio:'pipe'});
    const listing=execFileSync('tar',['-tzf','.rust-release-save.tar.gz'],{cwd:directory,encoding:'utf8'});
    assert.match(listing,/target\/release\/deps\/dependency.rlib/);
    assert.doesNotMatch(listing,/cache_fixture|credentials|profraw|profdata/);
    const source=JSON.parse(readFileSync(path.join(directory,'.rust-release-save/source.json'),'utf8'));
    assert.deepEqual(source,{target,sha:'a'.repeat(40),run_id:'123',run_attempt:'1'});
    assert.throws(()=>execFileSync(process.execPath,[script,'pack','release',target],{cwd:directory,env:{...producer,GITHUB_RUN_ATTEMPT:''},stdio:'pipe'}));
  } finally {rmSync(directory,{recursive:true});}
  const writer=section('rust-build-save');
  assert.match(writer,/cache-mode: write-only/);assert.match(writer,/filter='data'/);
  assert.match(writer,/\^rust-ci-v1-/);
  assert.doesNotMatch(writer,/actions\/checkout|secrets\.|cache\/restore|cargo |run: node/);
  for(const name of ['workspace-tests','coverage-tests']){
    const lane=section(name);assert.match(lane,/actions\/cache\/restore/);assert.doesNotMatch(lane,/cache-mode: write|cache\/save/);
    assert.match(lane,/steps.rust-build.outputs.cache-hit != 'true'/);
  }
});
