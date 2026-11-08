#!/usr/bin/env bash
set -euo pipefail

phase='coverage environment'
trap 'status=$?; printf "::error::Runtime business runner failed during %s at line %s (exit %s)\n" "$phase" "$LINENO" "$status" >&2; exit "$status"' ERR

: "${RUNNER_TEMP:?RUNNER_TEMP is required}"
: "${RSRS_RUNTIME_TEST_RUNNER:?Runtime business runner is required}"
: "${RUNTIME_BUSINESS_MODULES:?Runtime business modules are required}"

coverage_dir="$PWD/target/llvm-cov-target"
CARGO_LLVM_COV_TARGET_DIR="$coverage_dir" cargo llvm-cov show-env --sh > "$RUNNER_TEMP/cli-coverage.env"
source "$RUNNER_TEMP/cli-coverage.env"

phase='instrumentation validation'
# cargo-llvm-cov 0.9 defaults to a rustc wrapper instead of public RUSTFLAGS.
if [[ "${RUSTFLAGS:-}${CARGO_ENCODED_RUSTFLAGS:-}" != *instrument-coverage* ]]; then
  if [[ "${__CARGO_LLVM_COV_RUSTC_WRAPPER:-}" != 1 || -z "${RUSTC_WRAPPER:-}" || "${__CARGO_LLVM_COV_RUSTC_WRAPPER_RUSTFLAGS:-}" != *instrument-coverage* ]]; then
    printf '::error::Coverage instrumentation is missing from both direct flags and the active rustc wrapper\n' >&2
    exit 1
  fi
fi
if [[ "${LLVM_PROFILE_FILE:-}" != "$coverage_dir/"* ]]; then
  printf '::error::LLVM_PROFILE_FILE must remain under the existing instrumented CLI coverage directory\n' >&2
  exit 1
fi

phase='existing instrumented CLI identity'
export RSRS_CLI_BIN="$coverage_dir/debug/rsrs"
export RSRS_CLI_SOURCE_DIR="$PWD"
export RSRS_CLI_SOURCE_SHA="$(git rev-parse HEAD)"
test -x "$RSRS_CLI_BIN"
original_cli="$(sha256sum "$RSRS_CLI_BIN")"
unset GH_TOKEN GITHUB_TOKEN

business_status=0
native_seen=0
for module in $RUNTIME_BUSINESS_MODULES; do
  phase="business module $module"
  module_status=0
  if [[ "${RUNTIME_REQUIRE_NATIVE_STOP:-0}" == 1 && "$module" == diary_identity ]]; then
    native_seen=1
    # Successful native output contains private business data; retain it only on this VM.
    native_log="$(mktemp "$RUNNER_TEMP/native-stop-private.XXXXXX")"
    if "$RSRS_RUNTIME_TEST_RUNNER" "$module::" --test-threads=1 --show-output > "$native_log" 2>&1; then :; else module_status=$?; fi
    phase='safe native stop evidence'
    if node --input-type=module - "$native_log" "$module_status" <<'NODE'
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync, realpathSync} from 'node:fs';
import {dirname, join} from 'node:path';
import {execFileSync} from 'node:child_process';
const env = process.env;
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const git = directory => execFileSync('git', ['-C', directory, 'rev-parse', 'HEAD'], {encoding:'utf8'}).trim();
const source = git('.'), harnessSource = git('.runtime-examples');
assert.match(source, /^[a-f0-9]{40}$/);
assert.equal(source, env.RSRS_CLI_SOURCE_SHA);
assert.equal(source, env.GITHUB_SHA);
assert.equal(harnessSource, JSON.parse(readFileSync('runtime-tests-source.json', 'utf8')).source_sha);
const receipt = JSON.parse(readFileSync(join(dirname(dirname(dirname(env.RSRS_RUNTIME_BIN))), 'runtime.json'), 'utf8'));
assert.equal(hash(receipt.release.metadata_json), receipt.release.metadata_sha256);
const metadata = JSON.parse(receipt.release.metadata_json);
assert.equal(metadata.schema_version, 2);
assert.equal(metadata.runtime_version, JSON.parse(readFileSync('runtime-pin.json', 'utf8')).required);
assert.equal(metadata.source_commit, env.EXPECTED_RUNTIME_PRODUCT_SOURCE_SHA);
assert.equal(metadata.binary_sha256, receipt.sha256);
assert.equal(hash(readFileSync(realpathSync(env.RSRS_RUNTIME_BIN))), receipt.sha256);
const lines = readFileSync(process.argv[2], 'utf8').split(/\r?\n/);
const nativeName = 'diary_identity::native_stop_waits_and_explicit_force_reaps_real_core_without_replay';
const nativeTestOk = lines.filter(line => line === `test ${nativeName} ... ok`).length === 1;
const prefix = ['start','fixture_ready','memory_seeded','runtime_ready','provider_received','active_verified','stop_accepted'];
const suffix = ['same_key_checked','business_completed','runtime_stopped','store_unchanged','restarted','stale_rejected','restart_stopped','complete'];
const expected = ['normal','forced'].flatMap(mode => [...prefix, ...(mode === 'normal' ? ['normal_waited'] : ['force_identities_rejected','worker_reaped']), ...suffix]
  .map(stage => `NATIVE_STOP_CHECKPOINT mode=${mode} stage=${stage}`));
const actual = lines.filter(line => line.includes('NATIVE_STOP_CHECKPOINT'));
const complete = mode => JSON.stringify(actual.filter(line => line.startsWith(`NATIVE_STOP_CHECKPOINT mode=${mode} `))) ===
  JSON.stringify(expected.filter(line => line.startsWith(`NATIVE_STOP_CHECKPOINT mode=${mode} `)));
const normal = complete('normal'), forced = complete('forced');
const checkpointsExact = JSON.stringify(actual) === JSON.stringify(expected);
const diaryPassed = process.argv[3] === '0';
const passed = nativeTestOk && normal && forced && checkpointsExact && diaryPassed;
console.log(JSON.stringify({schema:1,evidence_class:'coverage-regression',gate:'not-evaluated',
  source_sha:source,run_id:env.GITHUB_RUN_ID,run_attempt:env.GITHUB_RUN_ATTEMPT,
  cli_binary_sha256:hash(readFileSync(env.RSRS_CLI_BIN)),runtime_tests_source_sha:harnessSource,
  harness_sha256:hash(readFileSync(env.RSRS_RUNTIME_TEST_RUNNER)),runtime_product_source_sha:metadata.source_commit,
  runtime_version:metadata.runtime_version,runtime_metadata_sha256:receipt.release.metadata_sha256,runtime_binary_sha256:receipt.sha256,
  native_test_ok:nativeTestOk,normal_checkpoints_complete:normal,forced_checkpoints_complete:forced,
  checkpoints_exact:checkpointsExact,diary_module_passed:diaryPassed,passed}));
if (!passed) process.exit(1);
NODE
    then :; elif [[ "$module_status" == 0 ]]; then module_status=1; fi
  elif "$RSRS_RUNTIME_TEST_RUNNER" "$module::" --test-threads=1; then
    :
  else
    module_status=$?
  fi
  if [[ "$business_status" == 0 && "$module_status" != 0 ]]; then business_status=$module_status; fi
done
if [[ "${RUNTIME_REQUIRE_NATIVE_STOP:-0}" == 1 && "$native_seen" != 1 && "$business_status" == 0 ]]; then business_status=1; fi

phase='unchanged instrumented CLI identity'
test "$(sha256sum "$RSRS_CLI_BIN")" = "$original_cli"
exit "$business_status"
