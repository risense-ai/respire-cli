import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {coveragePolicy, runCoverage} from './check-cli-coverage.mjs';
const cargo = version => `[package]\nname = "respire"\nversion = "${version}"\n[features]\ndefault = []\n`;
const report = (covered = 89, count = 100) => ({type: 'llvm.coverage.json.export', version: '3.1.0', data: [{totals: {lines: {count, covered, percent: count ? covered / count * 100 : 0}}}]});
const evaluate = (version, covered, candidate = 'false') => coveragePolicy(cargo(version), {cliVersion: version}, report(covered), candidate);
test('only exact DEV releases receive advisory coverage, never frozen candidates', () => {
  for (const covered of [0, 89, 90, 100]) assert.equal(evaluate('1.0.21-dev.5', covered).pass, true);
  for (const version of ['1.0.21', '1.0.21-rc.1', '1.0.21-beta.2', '1.0.21-dev.5+build']) {
    assert.equal(evaluate(version, 89).pass, false);
    assert.equal(evaluate(version, 90).pass, true);
  }
  assert.equal(evaluate('1.0.21-dev.5', 89, 'true').pass, false);
  assert.equal(evaluate('1.0.21-dev.5', 90, 'true').pass, true);
  assert.equal(coveragePolicy(cargo('1.0.21'), {cliVersion:'1.0.21'}, report(89999,100000)).pass, false);
});
test('versions, candidate mode, malformed or empty metrics fail closed', () => {
  for (const version of ['', 'latest', 'v1.0.21', '01.0.21', '1.0.21-dev.05', '1.0.21-dev.']) assert.throws(() => evaluate(version, 90));
  assert.throws(() => coveragePolicy(cargo('1.0.21-dev.5'), {cliVersion:'1.0.21-dev.6'}, report()));
  for (const mode of ['', 'TRUE', 'unknown']) assert.throws(() => evaluate('1.0.21-dev.5', 89, mode));
  assert.throws(() => coveragePolicy('[package]\nversion.workspace = true\n', {cliVersion:'1.0.21'}, report()));
  for (const bad of [null, {}, report(0,0), report(-1), report(101), report(1.5), report(1, Infinity), {...report(), data:[]}, {...report(), data:[report().data[0], report().data[0]]}, {...report(), version:'unknown'}]) {
    assert.throws(() => coveragePolicy(cargo('1.0.21-dev.5'), {cliVersion:'1.0.21-dev.5'}, bad));
  }
  const inconsistent = report(); inconsistent.data[0].totals.lines.percent = 90;
  assert.throws(() => coveragePolicy(cargo('1.0.21-dev.5'), {cliVersion:'1.0.21-dev.5'}, inconsistent));
});
test('report command failures and JSON errors cannot become advisory success', () => {
  const options = {cargo:cargo('1.0.21-dev.5'), manifest:{cliVersion:'1.0.21-dev.5'}, ignore:'original-regex'};
  for (const failAt of [1,2]) {
    let calls = 0;
    assert.throws(() => runCoverage({...options, execute:() => { if (++calls === failAt) throw new Error('cargo exited 1'); return ''; }}), /cargo exited 1/);
    assert.equal(calls, failAt);
  }
  assert.throws(() => runCoverage({...options, execute:() => 'malformed JSON'}));
  const calls = [], messages = [];
  const result = runCoverage({...options, execute:(command,args) => { calls.push([command,args]); return JSON.stringify(report()); }, log:message => messages.push(message)});
  assert.equal(result.pass,true);
  assert(messages.some(message => message.startsWith('::warning::')));
  assert(messages.some(message => message.includes('89/100')));
  for (const [command,args] of calls) { assert.equal(command,'cargo'); assert.deepEqual(args.slice(0,6), ['llvm-cov','report','-p','respire','--ignore-filename-regex','original-regex']); }
  assert.deepEqual(calls[0][1].slice(6), ['--show-missing-lines']);
  assert.deepEqual(calls[1][1].slice(6), ['--json','--summary-only']);
});
test('both workflows use the same policy and preserve candidate hard gating', () => {
  const ci=readFileSync(new URL('../.github/workflows/ci.yml',import.meta.url),'utf8');
  const token=readFileSync(new URL('../.github/workflows/token-free-sdk-check.yml',import.meta.url),'utf8');
  const pattern=/node scripts\/check-cli-coverage\.mjs '([^']+)'/;
  assert.equal(ci.match(pattern)?.[1], token.match(pattern)?.[1]);
  assert(ci.match(pattern)?.[1].includes('cli/src/frontend'));
  const step=ci.split('- name: CLI line coverage (')[1].split('- name: Require source')[0];
  assert(step.includes("CANDIDATE_MODE: ${{ inputs.required_candidate_run_id != '' || inputs.required_candidate_artifact_id != '' || inputs.required_candidate_sha256 != '' }}"));
  assert.doesNotMatch(step, /continue-on-error|\|\| true/);
  assert(ci.includes('scripts/test-cli-coverage-policy.mjs'));
});
