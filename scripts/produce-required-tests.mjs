#!/usr/bin/env node

// Only the two mapped CLI source tests. This never certifies published assets.
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { closeSync, copyFileSync, existsSync, lstatSync, mkdirSync, openSync, readFileSync, readdirSync, realpathSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { gunzipSync } from 'node:zlib';
import { inspectArchive } from '../crates/core-sdk/prepare-sdk.mjs';
import { auditSdkDirectory } from './sdk-ci-cache.mjs';

const target = 'x86_64-unknown-linux-gnu';
export const sourceCases = [
  'offline_install_publishes_manifest_and_retains_one_rollback',
  'metadata_validation_rejects_cross_purpose_documents',
];
const requireValue = (ok, message) => { if (!ok) throw Error(message); };
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const digest = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const ordinary = path => {
  const stat = lstatSync(path);
  requireValue(stat.isFile() && !stat.isSymbolicLink(), `Evidence is not an ordinary file: ${path}`);
  return readFileSync(path);
};
const json = path => JSON.parse(ordinary(path));
const save = (path, value) => writeFileSync(path, JSON.stringify(value, null, 2) + '\n', { flag: 'wx' });
const rawRoot = () => join(process.env.RUNNER_TEMP, 'required-tests-raw-cli-core');
const inputRoot = () => join(process.env.RUNNER_TEMP, 'required-tests-candidate-input');

export function runContext(env) {
  requireValue(/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(env.GITHUB_REPOSITORY ?? '') &&
    /^[a-f0-9]{40}$/i.test(env.GITHUB_SHA ?? '') &&
    /^[1-9][0-9]*$/.test(env.GITHUB_RUN_ID ?? '') && /^[1-9][0-9]*$/.test(env.GITHUB_RUN_ATTEMPT ?? '') &&
    env.GITHUB_JOB === 'coverage-tests' && env.RUNNER_OS === 'Linux' && env.RUNNER_ARCH === 'X64',
  'Require the current Linux X64 Coverage (core) run identity');
  return { repository: env.GITHUB_REPOSITORY, source_sha: env.GITHUB_SHA.toLowerCase(),
    run_id: env.GITHUB_RUN_ID, run_attempt: env.GITHUB_RUN_ATTEMPT, job_name: 'Coverage (core)', target };
}

export function verifyCandidate(bytes, expectedHash, context) {
  requireValue(digest(expectedHash) && hash(bytes) === expectedHash, 'Candidate input SHA-256 mismatch');
  const candidate = JSON.parse(bytes);
  requireValue(candidate.schema === 2, 'Candidate schema 2 required; v1 is not accepted');
  requireValue(candidate.frozen === true && candidate.gate === 'G1', 'Candidate must be an explicitly frozen G1 combination');
  requireValue(!Object.hasOwn(candidate, 'sdk'), 'Candidate schema 2 forbids ambiguous global sdk');
  for (const owner of ['runtime', 'cli', 'client2']) {
    const component = candidate.components?.[owner];
    requireValue(/^[a-f0-9]{40}$/i.test(component?.source_sha ?? '') && typeof component.version === 'string' &&
      component.version && component.artifacts && Object.keys(component.artifacts).length > 0,
    `Candidate lacks ${owner} source/version/artifacts`);
    for (const [name, artifact] of Object.entries(component.artifacts)) {
      requireValue(/^[a-z0-9_-]+$/.test(name) && digest(artifact?.archive_sha256) && digest(artifact?.binary_sha256),
        `Candidate has invalid ${owner}/${name} digests`);
      const native = artifact.native_sdk;
      requireValue(owner === 'client2' ? native === null : native && typeof native === 'object' && !Array.isArray(native) &&
        Object.keys(native).sort().join(',') === 'archive_sha256,manifest_sha256,version' &&
        typeof native.version === 'string' && native.version.trim() && digest(native.manifest_sha256) && digest(native.archive_sha256),
      `Candidate ${owner}/${name} requires native SDK identity, or explicit null for client2`);
    }
  }
  requireValue(candidate.components.cli.source_sha.toLowerCase() === context.source_sha && candidate.components.cli.artifacts[target],
    'Candidate CLI source or target differs from this run');
  return candidate;
}

// Cache preparation deliberately deletes the compressed archive. Require its actual
// bytes in the input artifact; the lock/candidate digest alone is not observation.
export function verifySdk(archive, manifestBytes, entry, expectedNativeSdk) {
  const archiveHash = hash(archive), manifestHash = hash(manifestBytes), manifest = JSON.parse(manifestBytes);
  requireValue(digest(entry?.archive_sha256) && archiveHash === entry.archive_sha256 &&
    digest(entry.manifest_sha256) && manifestHash === entry.manifest_sha256 && manifest?.target === target &&
    typeof manifest.sdk_version === 'string' && manifest.sdk_version.trim() && manifest.sdk_version === entry.sdk_version,
  'Actual SDK archive/manifest differs from the checked-out lock');
  requireValue(expectedNativeSdk?.version === manifest.sdk_version && expectedNativeSdk.archive_sha256 === archiveHash &&
    expectedNativeSdk.manifest_sha256 === manifestHash, 'Actual native SDK differs from candidate cli/' + target);
  inspectArchive(archive);
  requireValue(Array.isArray(manifest.files), 'SDK manifest files must be an array');
  const expected = new Map([['manifest.json', manifestHash]]);
  for (const file of manifest.files) {
    requireValue(file && typeof file.path === 'string' && file.path && !file.path.includes('\\') &&
      file.path.split('/').every(part => part && part !== '.' && part !== '..') &&
      !expected.has(file.path) && digest(file.sha256), 'Duplicate/invalid SDK manifest entry');
    expected.set(file.path, file.sha256);
  }
  const bytes = gunzipSync(archive), seen = new Set();
  const text = data => data.toString('utf8').split('\0')[0];
  for (let offset = 0; offset + 512 <= bytes.length;) {
    const header = bytes.subarray(offset, offset + 512);
    if (header.every(byte => byte === 0)) break;
    const size = Number.parseInt(text(header.subarray(124, 136)).trim(), 8);
    const name = [text(header.subarray(345, 500)), text(header.subarray(0, 100))].filter(Boolean).join('/').replace(/^\.\//, '');
    if (header[156] === 53) {
      const directory = name.replace(/\/$/, '');
      requireValue(directory === '.' || directory === '' || [...expected.keys()].some(path => path.startsWith(directory + '/')),
        `Unexpected SDK archive directory: ${name}`);
    } else {
      requireValue(!seen.has(name) && expected.has(name) && hash(bytes.subarray(offset + 512, offset + 512 + size)) === expected.get(name),
        `SDK archive payload differs from the installed manifest: ${name}`);
      seen.add(name);
    }
    offset += 512 + Math.ceil(size / 512) * 512;
  }
  requireValue(seen.size === expected.size, 'SDK archive is incomplete');
  return { version: manifest.sdk_version, archive_sha256: archiveHash, manifest_sha256: manifestHash };
}

export function parseSourceOutput(stdout, execution) {
  requireValue(execution.exit_code === 0 && execution.signal === null && execution.error === null,
    'Source command did not exit successfully');
  let suite = null, suites = 0, total = 0, passed = 0, ignored = 0;
  const requiredNames = sourceCases.map(name => `runtime_fetch::runtime_fetch_tests::${name}`);
  const hits = new Map(requiredNames.map(name => [name, []]));
  for (const line of stdout.split(/\r?\n/)) {
    let match = /^running ([0-9]+) tests?$/.exec(line);
    if (match) {
      requireValue(suite === null, 'Incomplete source test suite');
      suite = { announced: Number(match[1]), passed: 0, ignored: 0, failed: 0 };
      continue;
    }
    match = /^test (\S+) \.\.\. (ok|FAILED|ignored)(?:,.*)?$/.exec(line);
    if (match) {
      requireValue(suite !== null, 'Test result without suite count');
      suite[match[2] === 'ok' ? 'passed' : match[2] === 'ignored' ? 'ignored' : 'failed']++;
      hits.get(match[1])?.push(match[2]);
      continue;
    }
    match = /^test result: (ok|FAILED)\. ([0-9]+) passed; ([0-9]+) failed; ([0-9]+) ignored; ([0-9]+) measured; ([0-9]+) filtered out; finished in .+$/.exec(line);
    if (match) {
      requireValue(suite !== null && match[1] === 'ok' && Number(match[3]) === 0 && Number(match[5]) === 0 &&
        suite.passed === Number(match[2]) && suite.failed === 0 && suite.ignored === Number(match[4]) &&
        suite.announced === suite.passed + suite.ignored, 'Source test counts or summary mismatch');
      suites++; total += suite.announced; passed += suite.passed; ignored += suite.ignored; suite = null;
    }
  }
  requireValue(suite === null && suites > 0 && total > 0, 'Source output is empty or incomplete');
  for (const [name, statuses] of hits) requireValue(statuses.length === 1 && statuses[0] === 'ok',
    `Required source case missing, duplicated, failed or ignored: ${name}`);
  return { suites, total, passed, ignored, cases: sourceCases.map((name, i) => ({ name, full_name: requiredNames[i], status: 'passed' })) };
}

const positiveId = value => typeof value === 'string' && /^[1-9][0-9]*$/.test(value);
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const candidateKeys = ['REQUIRED_CANDIDATE_SHA256', 'REQUIRED_CANDIDATE_RUN_ID', 'REQUIRED_CANDIDATE_ARTIFACT_ID'];
const timestamp = value => typeof value === 'string' && Number.isFinite(Date.parse(value)) &&
  new Date(value).toISOString() === value;
const nativeShape = sdk => sdk && typeof sdk === 'object' && !Array.isArray(sdk) &&
  Object.keys(sdk).sort().join(',') === 'archive_sha256,manifest_sha256,version' &&
  typeof sdk.version === 'string' && sdk.version.trim() && digest(sdk.archive_sha256) && digest(sdk.manifest_sha256);
function validateCommand(command) {
  const prefix = ['cargo', 'llvm-cov', '--locked', '-p', 'respire', '--no-report', '--lib', '--bins', '--examples'];
  requireValue(Array.isArray(command) && prefix.every((arg, i) => command[i] === arg) &&
    (command.length - prefix.length) % 2 === 0, 'Unexpected source command');
  const tests = new Set();
  for (let i = prefix.length; i < command.length; i += 2) {
    requireValue(command[i] === '--test' && typeof command[i + 1] === 'string' &&
      /^[A-Za-z0-9_-]+$/.test(command[i + 1]) && !tests.has(command[i + 1]), 'Unexpected source command');
    tests.add(command[i + 1]);
  }
}

function validatedInputs(context) {
  requireValue(positiveId(process.env.REQUIRED_CANDIDATE_RUN_ID) && positiveId(process.env.REQUIRED_CANDIDATE_ARTIFACT_ID),
    'Candidate input IDs must be positive integer strings');
  requireValue(readdirSync(inputRoot()).sort().join(',') === 'candidate.json,sdk.tar.gz',
    'Candidate input must contain only candidate.json and sdk.tar.gz');
  const bytes = ordinary(join(inputRoot(), 'candidate.json'));
  const candidate = verifyCandidate(bytes, process.env.REQUIRED_CANDIDATE_SHA256, context);
  const archivePath = join(inputRoot(), 'sdk.tar.gz');
  requireValue(existsSync(archivePath), 'SDK archive evidence missing: input artifact must contain sdk.tar.gz; the SDK cache retains only extracted files');
  const entry = json('sdk/core-sdk.lock.json').targets[target];
  requireValue(process.env.RSRS_CORE_SDK_DIR, 'Prepared SDK directory is missing');
  const directory = resolve(process.env.RSRS_CORE_SDK_DIR);
  auditSdkDirectory(directory, target, entry);
  const sdk = verifySdk(ordinary(archivePath), ordinary(join(directory, 'manifest.json')), entry,
    candidate.components.cli.artifacts[target].native_sdk);
  return { bytes, binding: { ...context, candidate_sha256: hash(bytes), actual_native_sdk: sdk,
    candidate_run_id: process.env.REQUIRED_CANDIDATE_RUN_ID, candidate_artifact_id: process.env.REQUIRED_CANDIDATE_ARTIFACT_ID,
    sdk_directory: directory, sdk_real_directory: realpathSync(directory) } };
}

export function prepare() {
  const started_at = new Date().toISOString();
  const context = runContext(process.env), { bytes, binding } = validatedInputs(context);
  requireValue(!existsSync(rawRoot()), 'Prepare requires a fresh raw directory; existing raw cannot be promoted');
  mkdirSync(rawRoot(), { recursive: true });
  writeFileSync(join(rawRoot(), 'candidate.json'), bytes, { flag: 'wx' });
  save(join(rawRoot(), 'preflight.json'), { schema: 2, ...binding, started_at, completed_at: new Date().toISOString() });
}

function verifiedPreflight(context) {
  const preflightBytes = ordinary(join(rawRoot(), 'preflight.json')), preflight = JSON.parse(preflightBytes);
  const { bytes, binding } = validatedInputs(context);
  for (const [key, value] of Object.entries(binding)) requireValue(same(preflight[key], value), `Prepare input differs: ${key}`);
  requireValue(preflight.schema === 2 && timestamp(preflight.started_at) && timestamp(preflight.completed_at) &&
    preflight.started_at <= preflight.completed_at && Date.parse(preflight.completed_at) <= Date.now() &&
    ordinary(join(rawRoot(), 'candidate.json')).equals(bytes), 'Invalid prepare bytes or timestamps');
  return { preflight, preflight_sha256: hash(preflightBytes) };
}

export function captureCoverage(args) {
  const context = runContext(process.env), directory = rawRoot();
  // Raw source output is never retroactively promoted to candidate evidence.
  const bound = candidateKeys.some(key => Object.hasOwn(process.env, key)) || existsSync(inputRoot()) ||
    existsSync(join(directory, 'preflight.json')) || existsSync(join(directory, 'candidate.json'));
  const prepared = bound ? verifiedPreflight(context) : null;
  if (bound) validateCommand(['cargo', ...args]);
  requireValue(!['stdout.log', 'stderr.log', 'execution.json'].some(name => existsSync(join(directory, name))),
    'Capture requires fresh logs and execution; existing raw cannot be promoted');
  mkdirSync(directory, { recursive: true });
  const started_at = new Date().toISOString();
  const stdout = openSync(join(directory, 'stdout.log'), 'wx'), stderr = openSync(join(directory, 'stderr.log'), 'wx');
  let result;
  try { result = spawnSync('cargo', args, { stdio: ['inherit', stdout, stderr], env: { ...process.env, CARGO_TERM_COLOR: 'never' } }); }
  finally { closeSync(stdout); closeSync(stderr); }
  const out = ordinary(join(directory, 'stdout.log')), err = ordinary(join(directory, 'stderr.log'));
  save(join(directory, 'execution.json'), { schema: 1, ...context, command: ['cargo', ...args], started_at,
    completed_at: new Date().toISOString(), exit_code: result.status, signal: result.signal ?? null,
    error: result.error?.message ?? null, stdout_sha256: hash(out), stderr_sha256: hash(err),
    evidence_class: bound ? 'candidate-source' : 'source-raw',
    candidate_sha256: prepared?.preflight.candidate_sha256 ?? null,
    actual_native_sdk: prepared?.preflight.actual_native_sdk ?? null,
    preflight_sha256: prepared?.preflight_sha256 ?? null,
    sdk_directory: prepared?.preflight.sdk_directory ?? null,
    sdk_real_directory: prepared?.preflight.sdk_real_directory ?? null,
    candidate_run_id: prepared?.preflight.candidate_run_id ?? null,
    candidate_artifact_id: prepared?.preflight.candidate_artifact_id ?? null, gate: 'not-evaluated' });
  process.stdout.write(out); process.stderr.write(err);
  return result.status ?? 1;
}

export function buildReports(context, preflight, execution, stdout, stderr, artifactId) {
  requireValue(same(context, runContext({ GITHUB_REPOSITORY: context.repository, GITHUB_SHA: context.source_sha,
    GITHUB_RUN_ID: context.run_id, GITHUB_RUN_ATTEMPT: context.run_attempt,
    GITHUB_JOB: 'coverage-tests', RUNNER_OS: 'Linux', RUNNER_ARCH: 'X64' })), 'Invalid report context');
  for (const key of Object.keys(context)) requireValue(preflight[key] === context[key] && execution[key] === context[key],
    `Evidence context differs: ${key}`);
  requireValue(preflight.schema === 2 && execution.schema === 1 && execution.evidence_class === 'candidate-source' &&
    execution.gate === 'not-evaluated' && digest(execution.preflight_sha256) &&
    digest(preflight.candidate_sha256) && execution.candidate_sha256 === preflight.candidate_sha256 &&
    nativeShape(preflight.actual_native_sdk) && nativeShape(execution.actual_native_sdk) &&
    same(execution.actual_native_sdk, preflight.actual_native_sdk),
  'Missing or changed pre-execution candidate/SDK binding');
  requireValue(execution.preflight_sha256 === hash(Buffer.from(JSON.stringify(preflight, null, 2) + '\n')),
    'Original preflight bytes differ from execution');
  for (const key of ['candidate_run_id', 'candidate_artifact_id', 'sdk_directory', 'sdk_real_directory'])
    requireValue(typeof preflight[key] === 'string' && preflight[key].length > 0 && execution[key] === preflight[key], `Invalid execution binding: ${key}`);
  requireValue(positiveId(preflight.candidate_run_id) && positiveId(preflight.candidate_artifact_id), 'Invalid candidate input IDs');
  requireValue([preflight.started_at, preflight.completed_at, execution.started_at, execution.completed_at].every(timestamp) &&
    preflight.started_at <= preflight.completed_at && preflight.completed_at <= execution.started_at &&
    execution.started_at <= execution.completed_at && Date.parse(execution.completed_at) <= Date.now(), 'Invalid evidence time order');
  validateCommand(execution.command);
  requireValue(hash(stdout) === execution.stdout_sha256 && hash(stderr) === execution.stderr_sha256, 'Raw output hash mismatch');
  requireValue(Number.isSafeInteger(artifactId) && artifactId > 0, 'Require the uploaded raw artifact ID');
  const parsed = parseSourceOutput(stdout.toString('utf8'), execution);
  const base = { schema: 2, ...context, status: 'passed', coverage: 'source-test', candidate_sha256: preflight.candidate_sha256,
    actual_native_sdk: preflight.actual_native_sdk, artifact_id: artifactId, artifact_name: `required-tests-raw-cli-core-${context.run_id}-${context.run_attempt}`,
    command: execution.command, exit_code: execution.exit_code, totals: { suites: parsed.suites, total: parsed.total, passed: parsed.passed, ignored: parsed.ignored },
    stdout_sha256: execution.stdout_sha256, stderr_sha256: execution.stderr_sha256 };
  return [
    { ...base, test_id: 'cli.release-metadata-dual-digest', cases: parsed.cases },
    { ...base, test_id: 'cli.release-metadata-legacy-mapping', cases: [parsed.cases[1]] },
  ];
}

export function produce() {
  const context = runContext(process.env), { preflight, preflight_sha256 } = verifiedPreflight(context);
  const execution = json(join(rawRoot(), 'execution.json'));
  requireValue(execution.preflight_sha256 === preflight_sha256, 'Original preflight bytes changed after capture');
  requireValue(positiveId(process.env.REQUIRED_RAW_ARTIFACT_ID), 'Require the uploaded raw artifact ID as a positive integer string');
  const reports = buildReports(context, preflight, execution,
    ordinary(join(rawRoot(), 'stdout.log')), ordinary(join(rawRoot(), 'stderr.log')), Number(process.env.REQUIRED_RAW_ARTIFACT_ID));
  const bundle = join(process.env.RUNNER_TEMP, 'required-tests-report-cli');
  mkdirSync(bundle); mkdirSync(join(bundle, 'reports'));
  copyFileSync(join(rawRoot(), 'candidate.json'), join(bundle, 'candidate.json'));
  for (const report of reports) save(join(bundle, 'reports', `${report.test_id}.json`), report);
  console.log('Produced two candidate-bound source-test reports; real-asset coverage remains missing.');
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  if (process.argv.length !== 3 || !['prepare', 'produce'].includes(process.argv[2])) throw Error('Usage: produce-required-tests.mjs prepare | produce');
  if (process.argv[2] === 'prepare') prepare(); else produce();
}
