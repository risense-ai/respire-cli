#!/usr/bin/env node

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync, writeSync } from "node:fs";
import childProcess from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
import { buildReports, captureCoverage, parseSourceOutput, prepare, produce, runContext, sourceCases, verifyCandidate, verifySdk } from "./produce-required-tests.mjs";
import { createHash } from "node:crypto";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { gunzipSync, gzipSync } from "node:zlib";
import { auditSdkDirectory } from "./sdk-ci-cache.mjs";

const verifier = fileURLToPath(new URL("./verify-required-tests.mjs", import.meta.url));
const repository = resolve(dirname(verifier), "..");
const evidenceRoot = join(repository, ".verification", "required-gate-selfcheck");
mkdirSync(evidenceRoot, { recursive: true });
const fixtureRoot = mkdtempSync(join(evidenceRoot, "case-"));
mkdirSync(join(fixtureRoot, "scripts"), { recursive: true });
mkdirSync(join(fixtureRoot, ".github", "workflows"), { recursive: true });
writeFileSync(join(fixtureRoot, ".github", "workflows", "fixture.yml"),
  "jobs:\n  fixture:\n    strategy:\n      matrix:\n        target: [target-a, target-b]\n    steps:\n      - run: |\n          node --eval gate.fixture\n");
writeFileSync(join(fixtureRoot, "fixture-source.txt"), "gate.fixture\n");

const sha = "a".repeat(40);
const nativeSdk = (owner, target) => owner === "client2" ? null : ({
  version: owner === "runtime" ? "1.0.2-dev.21" : "1.0.2-dev.20",
  manifest_sha256: createHash("sha256").update(owner + "/" + target + "/manifest").digest("hex"),
  archive_sha256: createHash("sha256").update(owner + "/" + target + "/archive").digest("hex"),
});
const goodJob = {
  name: "fixture", run_id: 17, head_sha: sha,
  status: "completed", conclusion: "success",
  started_at: "2026-11-04T01:00:00Z", completed_at: "2026-11-04T01:01:00Z",
};
const candidate = {
  schema: 2, frozen: true, gate: "G1",
  components: Object.fromEntries(["runtime", "cli", "client2"].map((owner) => [owner, {
    source_sha: sha, version: "fixture-only",
    artifacts: Object.fromEntries(["target-a", "target-b"].map(target => [target, {
      archive_sha256: "b".repeat(64), binary_sha256: "c".repeat(64), native_sdk: nativeSdk(owner, target),
    }])),
  }])),
};
const candidateText = JSON.stringify(candidate);
const report = {
  schema: 2, test_id: "gate.fixture", target: "target-a", coverage: "source-test",
  actual_native_sdk: nativeSdk("runtime", "target-a"),
  status: "passed", cases: [{ name: "gate.fixture", status: "passed" }],
  run_id: "17", run_attempt: "2", source_sha: sha, repository: "fixture/runtime",
  candidate_sha256: createHash("sha256").update(candidateText).digest("hex"),
  job_name: "fixture", artifact_id: 31, artifact_name: "required-tests-fixture-evidence",
};
const goodArtifact = {
  id: 31, name: report.artifact_name, expired: false,
  workflow_run: { id: 17, head_sha: sha }, created_at: "2026-11-04T01:00:30Z",
};
const ready = {
  id: "gate.fixture", area: "fixture", status: "implemented",
  report_schema: "required-execution/v2",
  coverage: "source-test", required_targets: ["target-a"],
  required_cases: ["gate.fixture"],
  source_suite: [{ file: "fixture-source.txt", test: "gate.fixture", command: "node --eval gate.fixture" }],
  evidence: {
    workflow: ".github/workflows/fixture.yml",
    job: "fixture", command_fragment: "node --eval gate.fixture",
  },
};
const cases = [
  { name: "current attempt", jobs: [goodJob] },
  { name: "old SHA", jobs: [{ ...goodJob, head_sha: "b".repeat(40) }], error: "different run or source SHA" },
  { name: "different run", jobs: [{ ...goodJob, run_id: 16 }], error: "different run or source SHA" },
  { name: "empty jobs", jobs: [], error: "did not execute exactly once" },
  { name: "skipped job", jobs: [{ ...goodJob, conclusion: "skipped" }], error: "did not execute exactly once" },
  { name: "cancelled job", jobs: [{ ...goodJob, conclusion: "cancelled" }], error: "did not execute exactly once" },
  { name: "missing attempt", jobs: [goodJob], attempt: "", error: "GitHub runtime environment" },
  { name: "foreign pagination", jobs: [goodJob], link: "<https://example.invalid/jobs>; rel=\"next\"", error: "escaped the selected run attempt" },
  { name: "empty manifest", tests: [], error: "manifest has no tests" },
  { name: "missing test", tests: [{ id: "gate.fixture", area: "fixture", status: "missing", reason: "fixture", report_schema: "required-execution/v2" }], error: "required tests are not implemented" },
  { name: "duplicate IDs", tests: [ready, ready], error: "duplicate test id" },
  { name: "legacy ready is not execution", tests: [{ ...ready, status: "ready" }], error: "implementation is not an execution result" },
  { name: "missing candidate", noCandidate: true, error: "final candidate combination is missing" },
  { name: "unfrozen draft candidate", candidate: { ...candidate, frozen: false }, error: "explicitly frozen G1 combination" },
  { name: "ambiguous global SDK", candidate: { ...candidate, sdk: null }, error: "forbids ambiguous global sdk" },
  { name: "wrong final source", candidate: { ...candidate, components: { ...candidate.components, runtime: { ...candidate.components.runtime, source_sha: "b".repeat(40) } } }, error: "different source SHA" },
  { name: "missing reports", noReports: true, error: "execution reports directory is missing" },
  { name: "empty reports", reports: [], error: "execution reports are empty" },
  { name: "zero tests", report: { ...report, cases: [] }, error: "empty, failed, skipped" },
  { name: "skipped test", report: { ...report, cases: [{ name: "gate.fixture", status: "skipped" }] }, error: "empty, failed, skipped" },
  { name: "failed report", report: { ...report, status: "failed" }, error: "empty, failed, skipped" },
  { name: "static report", report: { ...report, coverage: "static" }, error: "not an execution report" },
  { name: "mock report", report: { ...report, coverage: "mock" }, error: "not an execution report" },
  { name: "old report attempt", report: { ...report, run_attempt: "1" }, error: "does not match the final candidate" },
  { name: "old report run", report: { ...report, run_id: "16" }, error: "does not match the final candidate" },
  { name: "old report SHA", report: { ...report, source_sha: "b".repeat(40) }, error: "does not match the final candidate" },
  { name: "wrong candidate hash", report: { ...report, candidate_sha256: "0".repeat(64) }, error: "does not match the final candidate" },
  { name: "wrong repository", report: { ...report, repository: "other/runtime" }, error: "does not match the final candidate" },
  { name: "wrong target", report: { ...report, target: "target-b" }, error: "target set is missing or different" },
  { name: "duplicate report", reports: [report, report], error: "duplicate execution report" },
  { name: "unmapped source case", report: { ...report, cases: [{ name: "other", status: "passed" }] }, error: "required_case missing" },
  { name: "parent pass with skipped child", tests: [{ ...ready, required_cases: ["gate.fixture", "gate.fixture/symlink"] }], report: { ...report, cases: [{ name: "gate.fixture", status: "passed" }, { name: "gate.fixture/symlink", status: "skipped" }] }, error: "empty, failed, skipped" },
  { name: "parent pass with omitted child", tests: [{ ...ready, required_cases: ["gate.fixture", "gate.fixture/symlink"] }], error: "required_case missing: gate.fixture/symlink" },
  { name: "parent and mandatory child pass", tests: [{ ...ready, required_cases: ["gate.fixture", "gate.fixture/symlink"] }], report: { ...report, cases: [{ name: "gate.fixture", status: "passed" }, { name: "gate.fixture/symlink", status: "passed" }] } },
  { name: "real artifact still requires child", tests: [{ ...ready, coverage: "real-artifact", required_cases: ["gate.fixture", "gate.fixture/symlink"] }], report: { ...report, coverage: "real-artifact" }, error: "required_case missing: gate.fixture/symlink" },
  { name: "required cases absent", tests: [{ ...ready, required_cases: undefined }], error: "explicit required cases" },
  { name: "required cases empty", tests: [{ ...ready, required_cases: [] }], error: "required cases must be nonempty" },
  { name: "unit is not real artifact", tests: [{ ...ready, coverage: "real-artifact" }], error: "required coverage was not executed" },
  { name: "missing artifact", artifacts: [], error: "artifact is missing, stale" },
  { name: "wrong artifact id", report: { ...report, artifact_id: 32 }, error: "artifact is missing, stale" },
  { name: "duplicate artifact id", artifacts: [goodArtifact, goodArtifact], error: "artifact is missing, stale" },
  { name: "old attempt artifact", artifacts: [{ ...goodArtifact, created_at: "2026-11-03T00:00:00Z" }], error: "artifact is missing, stale" },
  { name: "expired artifact", artifacts: [{ ...goodArtifact, expired: true }], error: "artifact is missing, stale" },
  { name: "artifact old SHA", artifacts: [{ ...goodArtifact, workflow_run: { id: 17, head_sha: "b".repeat(40) } }], error: "artifact is missing, stale" },
  { name: "artifact foreign pagination", artifactLink: '<https://example.invalid/artifacts>; rel="next"', error: "artifact pagination escaped" },
  { name: "missing source", tests: [{ ...ready, source_suite: [{ ...ready.source_suite[0], file: "absent.txt" }] }], error: "mapped source test does not exist" },
  { name: "empty target matrix", tests: [{ ...ready, required_targets: [] }], error: "required targets must be nonempty" },
  {
    name: "missing matrix leg",
    tests: [{ ...ready, evidence: { ...ready.evidence, matrix: ["target-a", "target-b"] } }],
    jobs: [{ ...goodJob, name: "fixture (target-a)" }],
    error: "matrix is empty, skipped, or incomplete",
  },
  {
    name: "similarly named matrix leg",
    tests: [{ ...ready, evidence: { ...ready.evidence, matrix: ["target-a", "target-b"] } }],
    jobs: [{ ...goodJob, name: "fixture (target-a-extra)" }, { ...goodJob, name: "fixture (target-b)" }],
    error: "matrix is empty, skipped, or incomplete",
  },
];

// Each mutation uses synthetic native SDK bytes/identities, never a real CI result.
function v2Case(name, owner, mutate = () => {}, error) {
  const value = { owner, candidate: structuredClone(candidate), report: {
    ...structuredClone(report), repository: `fixture/${owner}`, actual_native_sdk: nativeSdk(owner, "target-a"),
  } };
  mutate(value);
  value.report.candidate_sha256 = createHash("sha256").update(JSON.stringify(value.candidate)).digest("hex");
  return { name, ...value, error };
}
cases.push(
  v2Case("CLI keeps dev.20 while Runtime keeps dev.21", "cli"),
  v2Case("Client2 explicit null", "client2"),
  v2Case("candidate v1 rejected", "runtime", v => { v.candidate.schema = 1; }, "candidate schema 2 required"),
  v2Case("report v1 rejected", "runtime", v => { v.report.schema = 1; }, "required-execution/v2 report schema required"),
  v2Case("registry v1 rejected", "runtime", v => { v.tests = [{...ready, report_schema: "required-execution/v1"}]; }, "required-execution/v2 report schema required"),
  v2Case("registry missing report schema", "runtime", v => { v.tests = [{...ready, report_schema: undefined}]; }, "required-execution/v2 report schema required"),
  v2Case("legacy report sdk rejected", "runtime", v => { v.report.sdk = nativeSdk("runtime", "target-a"); }, "forbids ambiguous global sdk"),
  v2Case("Client2 candidate missing null", "client2", v => { delete v.candidate.components.client2.artifacts["target-a"].native_sdk; }, "must be explicit null"),
  v2Case("Client2 candidate cannot claim Runtime SDK", "client2", v => { v.candidate.components.client2.artifacts["target-a"].native_sdk = nativeSdk("runtime", "target-a"); }, "must be explicit null"),
  v2Case("Client2 report missing null", "client2", v => { delete v.report.actual_native_sdk; }, "must be explicit null"),
  v2Case("Client2 report cannot claim Runtime SDK", "client2", v => { v.report.actual_native_sdk = nativeSdk("runtime", "target-a"); }, "must be explicit null"),
);
for (const owner of ["runtime", "cli"]) {
  cases.push(
    v2Case(`${owner} candidate missing SDK`, owner, v => { delete v.candidate.components[owner].artifacts["target-a"].native_sdk; }, "requires native SDK"),
    v2Case(`${owner} candidate null SDK`, owner, v => { v.candidate.components[owner].artifacts["target-a"].native_sdk = null; }, "requires native SDK"),
    v2Case(`${owner} report missing SDK`, owner, v => { delete v.report.actual_native_sdk; }, "requires native SDK"),
    v2Case(`${owner} report null SDK`, owner, v => { v.report.actual_native_sdk = null; }, "requires native SDK"),
    v2Case(`${owner} other owner SDK`, owner, v => { v.report.actual_native_sdk = nativeSdk(owner === "runtime" ? "cli" : "runtime", "target-a"); }, "actual native SDK differs"),
    v2Case(`${owner} other target SDK`, owner, v => { v.report.actual_native_sdk = nativeSdk(owner, "target-b"); }, "actual native SDK differs"),
    v2Case(`${owner} Rust wrapper is not native SDK`, owner, v => { v.report.actual_native_sdk.version = "2.0.0-dev.4"; }, "actual native SDK differs"),
  );
  for (const field of ["version", "manifest_sha256", "archive_sha256"]) {
    cases.push(
      v2Case(`${owner} candidate missing ${field}`, owner, v => { delete v.candidate.components[owner].artifacts["target-a"].native_sdk[field]; }, "requires native SDK"),
      v2Case(`${owner} actual wrong ${field}`, owner, v => { v.report.actual_native_sdk[field] = field === "version" ? "1.0.2-dev.999" : "0".repeat(64); }, "actual native SDK differs"),
    );
  }
}
// All target bindings coexist. Passing one target is not an eight-target result.
const nativeTargets = ["x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc", "x86_64-apple-darwin", "aarch64-apple-darwin",
  "x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu", "x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl"];
for (const owner of ["runtime", "cli", "client2"]) {
  const scenario = v2Case(`${owner} eight distinct target SDK bindings`, owner, v => {
    for (const component of ["runtime", "cli", "client2"]) v.candidate.components[component].artifacts =
      Object.fromEntries(nativeTargets.map(target => [target, {
        archive_sha256: "b".repeat(64), binary_sha256: "c".repeat(64), native_sdk: nativeSdk(component, target),
      }]));
    v.tests = [{...ready, required_targets: nativeTargets}];
  });
  scenario.reports = nativeTargets.map(target => ({...scenario.report, target, actual_native_sdk: nativeSdk(owner, target)}));
  cases.push(scenario, {...scenario, name: `${owner} eight-target reports cannot shrink`, reports: scenario.reports.slice(0, 1), error: "target set is missing or different"});
}


for (let index = 0; index < cases.length; index++) {
  const scenario = cases[index];
  const manifest = join(fixtureRoot, "scripts", `required-${index}.json`);
  const runRoot = join(fixtureRoot, `execution-${index}`);
  mkdirSync(runRoot);
  const candidateFile = join(runRoot, "candidate.json");
  if (!scenario.noCandidate) writeFileSync(candidateFile, scenario.candidate ? JSON.stringify(scenario.candidate) : candidateText);
  const reportsDir = join(runRoot, "reports");
  if (!scenario.noReports) {
    mkdirSync(reportsDir);
    for (const [reportIndex, item] of (scenario.reports ?? [scenario.report ?? report]).entries()) {
      writeFileSync(join(reportsDir, `${reportIndex}.json`), JSON.stringify(item));
    }
  }
  writeFileSync(manifest, JSON.stringify({
    schema: 1, owner: scenario.owner ?? "runtime", areas: ["fixture"], tests: scenario.tests ?? [ready],
  }));
  const mock = `
    process.argv = [process.execPath, ${JSON.stringify(verifier)}, "--ci", ${JSON.stringify(`--manifest=${manifest}`)},
      ${JSON.stringify(`--reports=${reportsDir}`)}, ${JSON.stringify(`--candidate=${candidateFile}`)}];
    globalThis.fetch = async (url) => {
      const artifacts = String(url).includes("/runs/17/artifacts?");
      if (!artifacts && !String(url).includes("/runs/17/attempts/2/jobs?")) {
        throw new Error("Jobs API did not select the exact run attempt");
      }
      return {
        ok: true,
        json: async () => artifacts
          ? (${JSON.stringify({ artifacts: scenario.artifacts ?? [goodArtifact] })})
          : (${JSON.stringify({ jobs: scenario.jobs ?? [goodJob] })}),
        headers: { get: () => artifacts ? ${JSON.stringify(scenario.artifactLink ?? null)} : ${JSON.stringify(scenario.link ?? null)} },
      };
    };
    await import(${JSON.stringify(pathToFileURL(verifier).href)});
  `;
  const result = spawnSync(process.execPath, ["--input-type=module", "--eval", mock], {
    cwd: fixtureRoot,
    encoding: "utf8",
    env: {
      ...(process.platform === "win32" ? { SystemRoot: process.env.SystemRoot } : {}),
      TEMP: fixtureRoot,
      TMP: fixtureRoot,
      GITHUB_API_URL: "https://api.github.com",
      GITHUB_REPOSITORY: `fixture/${scenario.owner ?? "runtime"}`,
      GITHUB_RUN_ID: "17",
      GITHUB_RUN_ATTEMPT: scenario.attempt ?? "2",
      GITHUB_SHA: sha,
      GITHUB_TOKEN: "fixture-only",
    },
  });
  assert.ifError(result.error);
  if (scenario.error) {
    assert.notEqual(result.status, 0, `${scenario.name} unexpectedly passed`);
    assert.ok(result.stderr.includes(scenario.error),
      `${scenario.name} failed for an unexpected reason: ${result.stderr}`);
  } else {
    assert.equal(result.status, 0, `${scenario.name}: ${result.stderr}`);
  }
  console.log(`PASS ${scenario.name}`);
}
console.log(`Required-gate self-check passed: ${cases.length} isolated fixture cases; no live API calls`);

// Pure source-output fixtures only: no Cargo/Go, SDK or candidate execution.
const fullNames = sourceCases.map(name => `runtime_fetch::runtime_fetch_tests::${name}`);
const sourceOutput = `running 2 tests\n${fullNames.map(name => `test ${name} ... ok`).join('\n')}\n` +
  'test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n';
const cleanExit = {exit_code: 0, signal: null, error: null};
let rawChecks = 0;
const rawCheck = (name, check) => { check(); rawChecks++; console.log(`PASS raw ${name}`); };
rawCheck('exact names and totals', () => assert.deepEqual(parseSourceOutput(sourceOutput, cleanExit), {
  suites: 1, total: 2, passed: 2, ignored: 0,
  cases: sourceCases.map((name, index) => ({name, full_name: fullNames[index], status: 'passed'})),
}));
for (const [name, output, execution] of [
  ['empty output', '', cleanExit],
  ['truncated output', sourceOutput.split('test result:')[0], cleanExit],
  ['wrong count', sourceOutput.replace('running 2', 'running 3'), cleanExit],
  ['missing exact case', sourceOutput.replace(fullNames[0], 'other::test'), cleanExit],
  ['duplicate exact cases', sourceOutput + sourceOutput, cleanExit],
  ['ignored required case', sourceOutput.replace(`${fullNames[0]} ... ok`, `${fullNames[0]} ... ignored`).replace('2 passed; 0 failed; 0 ignored', '1 passed; 0 failed; 1 ignored'), cleanExit],
  ['failed exit', sourceOutput, {...cleanExit, exit_code: 7}],
  ['signal', sourceOutput, {...cleanExit, signal: 'SIGTERM'}],
  ['spawn error', sourceOutput, {...cleanExit, error: 'ENOENT'}],
]) rawCheck(name, () => assert.throws(() => parseSourceOutput(output, execution)));
// Build actual gzip/ustar bytes in memory; refreshed fixture pins let payload failures reach inspection.
const sdkHash = bytes => createHash('sha256').update(bytes).digest('hex');
function sdkArchive(members) {
  const blocks = [];
  for (const {path, bytes = Buffer.alloc(0), type = '0'} of members) {
    const header = Buffer.alloc(512);
    header.write(path, 0, 100);
    header.write('0000644\0', 100);
    header.write('0000000\0', 108); header.write('0000000\0', 116);
    header.write(bytes.length.toString(8).padStart(11, '0') + '\0', 124);
    header.write('00000000000\0', 136);
    header.fill(32, 148, 156); header.write(type, 156);
    header.write('ustar\0', 257); header.write('00', 263);
    const checksum = header.reduce((sum, byte) => sum + byte, 0);
    header.write(checksum.toString(8).padStart(6, '0') + '\0 ', 148);
    blocks.push(header, bytes, Buffer.alloc((512 - bytes.length % 512) % 512));
  }
  return gzipSync(Buffer.concat([...blocks, Buffer.alloc(1024)]));
}
const sdkPayload = Buffer.from('synthetic native archive payload\n');
const sdkManifest = {
  target: 'x86_64-unknown-linux-gnu', sdk_version: '1.0.2-dev.20', abi_version: 0x10002,
  inference_thread_contract: 1, association_contract: 1, models_bundled: false,
  redistribution: 'permitted-under-included-license',
  files: [{path: 'lib/core.a', sha256: sdkHash(sdkPayload)}],
};
function sdkFixture(changeManifest = () => {}, changeMembers = () => {}) {
  const manifest = structuredClone(sdkManifest);
  changeManifest(manifest);
  const manifestBytes = Buffer.from(JSON.stringify(manifest));
  const members = [{path: 'manifest.json', bytes: manifestBytes}, {path: 'lib/', type: '5'},
    {path: 'lib/core.a', bytes: sdkPayload}];
  changeMembers(members);
  const archive = sdkArchive(members);
  const entry = {sdk_version: sdkManifest.sdk_version, manifest_sha256: sdkHash(manifestBytes), archive_sha256: sdkHash(archive)};
  const native = {version: sdkManifest.sdk_version, manifest_sha256: entry.manifest_sha256, archive_sha256: entry.archive_sha256};
  return {archive, manifestBytes, entry, native};
}
const verifyFixtureSdk = f => verifySdk(f.archive, f.manifestBytes, f.entry, f.native);
rawCheck('SDK actual bytes produce independent identity', () => {
  const f = sdkFixture(), result = verifyFixtureSdk(f);
  assert.deepEqual(result, {version: JSON.parse(f.manifestBytes).sdk_version,
    archive_sha256: sdkHash(f.archive), manifest_sha256: sdkHash(f.manifestBytes)});
  assert.notEqual(result, f.native);
  const directory = join(fixtureRoot, 'sdk-audit');
  mkdirSync(join(directory, 'lib'), {recursive: true});
  writeFileSync(join(directory, 'manifest.json'), f.manifestBytes);
  writeFileSync(join(directory, 'lib/core.a'), sdkPayload);
  assert.deepEqual(auditSdkDirectory(directory, sdkManifest.target, f.entry), JSON.parse(f.manifestBytes));
  writeFileSync(join(directory, 'lib/core.a'), 'corrupt');
  assert.throws(() => auditSdkDirectory(directory, sdkManifest.target, f.entry), /corrupt/);
});
for (const field of ['sdk_version', 'manifest_sha256', 'archive_sha256']) {
  rawCheck(`SDK checked-out lock mismatch ${field}`, () => {
    const f = sdkFixture(); f.entry[field] = field === 'sdk_version' ? '1.0.2-dev.21' : '0'.repeat(64);
    assert.throws(() => verifyFixtureSdk(f), /checked-out lock/);
  });
}
for (const field of ['version', 'manifest_sha256', 'archive_sha256']) {
  rawCheck(`SDK candidate mismatch ${field}`, () => {
    const f = sdkFixture(); f.native[field] = field === 'version' ? '1.0.2-dev.21' : '0'.repeat(64);
    assert.throws(() => verifyFixtureSdk(f), /candidate cli/);
  });
}
for (const [name, mutate, error] of [
  ['other owner SDK', f => { f.native = nativeSdk('runtime', sdkManifest.target); }, /candidate cli/],
  ['other target SDK', f => { f.native = nativeSdk('cli', 'aarch64-unknown-linux-gnu'); }, /candidate cli/],
  ['Client2 null SDK', f => { f.native = null; }, /candidate cli/],
  ['absent candidate SDK', f => { f.native = undefined; }, /candidate cli/],
  ['changed standalone manifest bytes', f => { f.manifestBytes = Buffer.concat([f.manifestBytes, Buffer.from('\n')]); }, /checked-out lock/],
  ['changed compressed archive bytes', f => { f.archive = Buffer.concat([f.archive, Buffer.from([0])]); }, /checked-out lock/],
]) rawCheck(`SDK rejects ${name}`, () => {
  const f = sdkFixture(); mutate(f); assert.throws(() => verifyFixtureSdk(f), error);
});
for (const [name, changeManifest, changeMembers, error] of [
  ['wrong manifest target', m => { m.target = 'aarch64-unknown-linux-gnu'; }, undefined, /checked-out lock/],
  ['wrong manifest version', m => { m.sdk_version = '1.0.2-dev.21'; }, undefined, /checked-out lock/],
  ['missing file list', m => { delete m.files; }, undefined, /files must be an array/],
  ['duplicate manifest file', m => { m.files.push({...m.files[0]}); }, undefined, /manifest entry/],
  ['reserved manifest file', m => { m.files.push({path: 'manifest.json', sha256: 'a'.repeat(64)}); }, undefined, /manifest entry/],
  ['unsafe manifest path', m => { m.files[0].path = '../outside'; }, undefined, /manifest entry/],
  ['invalid payload digest', m => { m.files[0].sha256 = 'invalid'; }, undefined, /manifest entry/],
  ['wrong payload digest', m => { m.files[0].sha256 = '0'.repeat(64); }, undefined, /payload differs/],
  ['duplicate archive file', undefined, a => { a.push({...a[2]}); }, /Duplicate tar entry/],
  ['duplicate archive manifest', undefined, a => { a.push({...a[0]}); }, /Duplicate tar entry/],
  ['extra archive file', undefined, a => { a.push({path: 'extra.txt', bytes: sdkPayload}); }, /payload differs/],
  ['extra archive directory', undefined, a => { a.push({path: 'extra/', type: '5'}); }, /Unexpected SDK archive directory/],
  ['missing payload', undefined, a => { a.pop(); }, /incomplete/],
  ['missing archive manifest', undefined, a => { a.shift(); }, /incomplete/],
  ['corrupt payload', undefined, a => { a[2].bytes = Buffer.from('corrupt'); }, /payload differs/],
  ['different archive manifest', undefined, a => { a[0].bytes = Buffer.from('{}'); }, /payload differs/],
  ['traversal member', undefined, a => { a[2].path = '../outside'; }, /Invalid SDK relative path/],
  ['absolute member', undefined, a => { a[2].path = '/outside'; }, /Invalid SDK relative path/],
  ['symlink member', undefined, a => { a[2].type = '2'; }, /links and special entries/],
  ['hardlink member', undefined, a => { a[2].type = '1'; }, /links and special entries/],
]) rawCheck(`SDK rejects ${name} with matching fixture pins`, () => {
  assert.throws(() => verifyFixtureSdk(sdkFixture(changeManifest, changeMembers)), error);
});
for (const [name, mutate, error] of [
  ['broken gzip', archive => archive.subarray(0, archive.length - 8), /unexpected end/i],
  ['tar checksum', archive => { const bytes = gunzipSync(archive); bytes[0] ^= 1; return gzipSync(bytes); }, /checksum mismatch/],
  ['truncated tar payload', archive => gzipSync(gunzipSync(archive).subarray(0, 512 + 10)), /Truncated tar entry/],
]) rawCheck(`SDK rejects ${name} after digest matching`, () => {
  const f = sdkFixture(); f.archive = mutate(f.archive);
  f.entry.archive_sha256 = f.native.archive_sha256 = sdkHash(f.archive);
  assert.throws(() => verifyFixtureSdk(f), error);
});
rawCheck('report generation requires evidence', () => assert.throws(() => buildReports()));
const producerCandidate = structuredClone(candidate);
for (const owner of ['runtime', 'cli', 'client2']) producerCandidate.components[owner].artifacts = {
  'x86_64-unknown-linux-gnu': {archive_sha256: 'b'.repeat(64), binary_sha256: 'c'.repeat(64),
    native_sdk: nativeSdk(owner, 'x86_64-unknown-linux-gnu')},
};
const checkProducerCandidate = value => {
  const bytes = Buffer.from(JSON.stringify(value));
  return verifyCandidate(bytes, createHash('sha256').update(bytes).digest('hex'), {source_sha: sha});
};
rawCheck('producer accepts mixed component SDK v2', () => assert.equal(checkProducerCandidate(producerCandidate).schema, 2));
rawCheck('producer rejects v1', () => assert.throws(() => checkProducerCandidate({...producerCandidate, schema: 1}), /schema 2 required/));
rawCheck('producer rejects unfrozen candidate', () => assert.throws(() => checkProducerCandidate({...producerCandidate, frozen: false}), /explicitly frozen/));
rawCheck('producer rejects global SDK', () => assert.throws(() => checkProducerCandidate({...producerCandidate, sdk: {}}), /global sdk/));
for (const owner of ['runtime', 'cli', 'client2']) rawCheck(`producer rejects absent native binding for ${owner}`, () => {
  const value = structuredClone(producerCandidate);
  delete value.components[owner].artifacts['x86_64-unknown-linux-gnu'].native_sdk;
  assert.throws(() => checkProducerCandidate(value), /requires native SDK identity/);
});
const contextEnv = {GITHUB_REPOSITORY: 'fixture/cli', GITHUB_SHA: sha, GITHUB_RUN_ID: '17',
  GITHUB_RUN_ATTEMPT: '2', GITHUB_JOB: 'coverage-tests', RUNNER_OS: 'Linux', RUNNER_ARCH: 'X64'};
rawCheck('reject non-native context', () => assert.throws(() => runContext({...contextEnv, RUNNER_ARCH: 'ARM64'})));
rawCheck('reject missing attempt', () => assert.throws(() => runContext({...contextEnv, GITHUB_RUN_ATTEMPT: ''})));

// Replace the child-process binding, not the executable. These checks cannot start Cargo.
const originalSpawn = childProcess.spawnSync;
const envKeys = [...Object.keys(contextEnv), 'RUNNER_TEMP', 'REQUIRED_CANDIDATE_SHA256',
  'REQUIRED_CANDIDATE_RUN_ID', 'REQUIRED_CANDIDATE_ARTIFACT_ID', 'RSRS_CORE_SDK_DIR', 'REQUIRED_RAW_ARTIFACT_ID'];
const originalEnv = Object.fromEntries(envKeys.map(key => [key, process.env[key]]));
try {
  Object.assign(process.env, contextEnv);
  for (const key of envKeys.filter(key => !Object.hasOwn(contextEnv, key))) delete process.env[key];
  for (const status of [0, 23, null]) {
    const localTemp = join(fixtureRoot, `raw-capture-${status}`);
    mkdirSync(localTemp); process.env.RUNNER_TEMP = localTemp;
    let calls = 0;
    childProcess.spawnSync = (command, args, options) => {
      calls++;
      assert.equal(command, 'cargo'); assert.deepEqual(args, ['fixture-only']);
      writeSync(options.stdio[1], sourceOutput); writeSync(options.stdio[2], 'fixture stderr\n');
      return {status, signal: status === null ? 'SIGTERM' : null};
    };
    syncBuiltinESMExports();
    rawCheck(`capture preserves exit ${status}`, () => {
      assert.equal(captureCoverage(['fixture-only']), status ?? 1);
      assert.equal(calls, 1);
      const directory = join(localTemp, 'required-tests-raw-cli-core');
      const result = JSON.parse(readFileSync(join(directory, 'execution.json')));
      assert.equal(result.exit_code, status); assert.equal(result.candidate_sha256, null);
      assert.equal(result.actual_native_sdk, null); assert.equal(result.evidence_class, 'source-raw');
      assert.equal(result.gate, 'not-evaluated'); assert.equal(result.run_attempt, '2');
      assert.equal(readFileSync(join(directory, 'stdout.log'), 'utf8'), sourceOutput);
      for (const stream of ['stdout', 'stderr']) assert.equal(result[stream + '_sha256'],
        createHash('sha256').update(readFileSync(join(directory, stream + '.log'))).digest('hex'));
    });
  }
  for (const binding of ['candidate', 'preflight']) rawCheck(`capture refuses ${binding} promotion`, () => {
    const localTemp = join(fixtureRoot, `raw-bound-${binding}`);
    mkdirSync(localTemp); process.env.RUNNER_TEMP = localTemp;
    if (binding === 'candidate') process.env.REQUIRED_CANDIDATE_SHA256 = 'a'.repeat(64);
    else {
      delete process.env.REQUIRED_CANDIDATE_SHA256;
      mkdirSync(join(localTemp, 'required-tests-raw-cli-core'));
      writeFileSync(join(localTemp, 'required-tests-raw-cli-core', 'preflight.json'), '{}');
    }
    childProcess.spawnSync = () => assert.fail('Bound raw capture must stop before spawning');
    syncBuiltinESMExports();
    assert.throws(() => captureCoverage(['fixture-only']), /preflight|Candidate input IDs/);
  });
} finally {
  childProcess.spawnSync = originalSpawn; syncBuiltinESMExports();
  for (const [key, value] of Object.entries(originalEnv)) {
    if (value === undefined) delete process.env[key]; else process.env[key] = value;
  }
}
for (const mode of ['prepare', 'produce']) rawCheck(`CLI ${mode} requires inputs`, () => {
  const result = spawnSync(process.execPath, [join(repository, 'scripts', 'produce-required-tests.mjs'), mode], {
    encoding: 'utf8', env: {...contextEnv, ...(process.platform === 'win32' ? {SystemRoot: process.env.SystemRoot} : {}),
      RUNNER_TEMP: fixtureRoot, TEMP: fixtureRoot, TMP: fixtureRoot},
  });
  assert.notEqual(result.status, 0); assert.match(result.stderr, /Candidate input IDs|preflight/);
});

// Exercise the complete chain against a synthetic lock and SDK under .verification.
const coverageArgs = ['llvm-cov', '--locked', '-p', 'respire', '--no-report', '--lib', '--bins', '--examples', '--test', 'fixture'];
const chainRoot = join(fixtureRoot, 'candidate-chain');
mkdirSync(join(chainRoot, 'sdk'), {recursive: true});
const fixtureSdk = sdkFixture();
writeFileSync(join(chainRoot, 'sdk', 'core-sdk.lock.json'), JSON.stringify({targets: {[sdkManifest.target]: fixtureSdk.entry}}));
let chainIndex = 0, spawnCalls = 0;
const originalCwd = process.cwd();
const writeJson = (path, value) => writeFileSync(path, JSON.stringify(value, null, 2) + '\n');
function chainFixture() {
  const localTemp = join(chainRoot, `chain-${chainIndex++}`), sdkDir = join(localTemp, 'installed-sdk');
  const inputs = join(localTemp, 'required-tests-candidate-input'), raw = join(localTemp, 'required-tests-raw-cli-core');
  mkdirSync(inputs, {recursive: true}); mkdirSync(join(sdkDir, 'lib'), {recursive: true});
  writeFileSync(join(sdkDir, 'manifest.json'), fixtureSdk.manifestBytes);
  writeFileSync(join(sdkDir, 'lib', 'core.a'), sdkPayload);
  const value = structuredClone(producerCandidate);
  value.components.cli.artifacts[sdkManifest.target].native_sdk = fixtureSdk.native;
  const bytes = Buffer.from(JSON.stringify(value));
  writeFileSync(join(inputs, 'candidate.json'), bytes); writeFileSync(join(inputs, 'sdk.tar.gz'), fixtureSdk.archive);
  Object.assign(process.env, contextEnv, {RUNNER_TEMP: localTemp, RSRS_CORE_SDK_DIR: sdkDir,
    REQUIRED_CANDIDATE_SHA256: sdkHash(bytes), REQUIRED_CANDIDATE_RUN_ID: '9', REQUIRED_CANDIDATE_ARTIFACT_ID: '11',
    REQUIRED_RAW_ARTIFACT_ID: '31'});
  return {localTemp, sdkDir, inputs, raw};
}
const readJson = path => JSON.parse(readFileSync(path));
try {
  process.chdir(chainRoot);
  childProcess.spawnSync = (command, args, options) => {
    spawnCalls++;
    assert.equal(command, 'cargo'); assert.deepEqual(args, coverageArgs);
    assert.equal(options.env.RSRS_CORE_SDK_DIR, process.env.RSRS_CORE_SDK_DIR);
    writeSync(options.stdio[1], sourceOutput); writeSync(options.stdio[2], 'synthetic stderr\n');
    return {status: 0, signal: null};
  };
  syncBuiltinESMExports();
  rawCheck('candidate prepare capture produce complete chain', () => {
    const f = chainFixture(); prepare();
    const original = readFileSync(join(f.raw, 'preflight.json'));
    assert.throws(prepare, /fresh raw directory/);
    assert.ok(original.equals(readFileSync(join(f.raw, 'preflight.json'))));
    assert.equal(captureCoverage(coverageArgs), 0);
    const execution = readJson(join(f.raw, 'execution.json'));
    assert.equal(execution.preflight_sha256, sdkHash(original));
    assert.equal(execution.sdk_directory, f.sdkDir);
    assert.deepEqual(execution.actual_native_sdk, fixtureSdk.native);
    produce();
    for (const id of ['cli.release-metadata-dual-digest', 'cli.release-metadata-legacy-mapping']) {
      const report = readJson(join(f.localTemp, 'required-tests-report-cli', 'reports', `${id}.json`));
      assert.equal(report.schema, 2); assert.equal(report.coverage, 'source-test'); assert.equal(report.artifact_id, 31);
      assert.deepEqual(report.actual_native_sdk, fixtureSdk.native); assert.equal(report.gate, undefined);
    }
    assert.ok(readFileSync(join(f.localTemp, 'required-tests-report-cli', 'candidate.json')).equals(readFileSync(join(f.inputs, 'candidate.json'))));
  });
  rawCheck('CLI prepare and produce accept validated synthetic inputs', () => {
    const f = chainFixture();
    const invoke = mode => originalSpawn(process.execPath, [join(repository, 'scripts', 'produce-required-tests.mjs'), mode], {
      cwd: chainRoot, encoding: 'utf8', env: {...process.env, TEMP: f.localTemp, TMP: f.localTemp},
    });
    const first = invoke('prepare'); assert.ifError(first.error); assert.equal(first.status, 0, first.stderr);
    const repeat = invoke('prepare'); assert.notEqual(repeat.status, 0); assert.match(repeat.stderr, /fresh raw directory/);
    captureCoverage(coverageArgs);
    const final = invoke('produce'); assert.ifError(final.error); assert.equal(final.status, 0, final.stderr);
  });
  for (const key of ['REQUIRED_CANDIDATE_SHA256', 'REQUIRED_CANDIDATE_RUN_ID', 'REQUIRED_CANDIDATE_ARTIFACT_ID'])
    rawCheck(`capture detects isolated ${key} even empty`, () => {
      const localTemp = join(chainRoot, `isolated-${chainIndex++}`); mkdirSync(localTemp);
      process.env.RUNNER_TEMP = localTemp;
      for (const name of ['REQUIRED_CANDIDATE_SHA256', 'REQUIRED_CANDIDATE_RUN_ID', 'REQUIRED_CANDIDATE_ARTIFACT_ID']) delete process.env[name];
      process.env[key] = ''; const before = spawnCalls;
      assert.throws(() => captureCoverage(coverageArgs), /preflight/); assert.equal(spawnCalls, before);
    });
  for (const [name, mutate] of [
    ['candidate hash only', () => { delete process.env.REQUIRED_CANDIDATE_RUN_ID; }],
    ['candidate run ID only', () => { delete process.env.REQUIRED_CANDIDATE_SHA256; }],
    ['candidate artifact ID only', () => { delete process.env.REQUIRED_CANDIDATE_SHA256; delete process.env.REQUIRED_CANDIDATE_RUN_ID; }],
    ['candidate input directory only', () => { for (const key of ['REQUIRED_CANDIDATE_SHA256', 'REQUIRED_CANDIDATE_RUN_ID', 'REQUIRED_CANDIDATE_ARTIFACT_ID']) delete process.env[key]; }],
  ]) rawCheck(`capture requires prepare with ${name}`, () => {
    chainFixture(); mutate(); const before = spawnCalls;
    assert.throws(() => captureCoverage(coverageArgs), /preflight/); assert.equal(spawnCalls, before);
  });
  for (const [name, mutate] of [
    ['old attempt', () => { process.env.GITHUB_RUN_ATTEMPT = '3'; }],
    ['old run', () => { process.env.GITHUB_RUN_ID = '18'; }],
    ['different candidate run ID', () => { process.env.REQUIRED_CANDIDATE_RUN_ID = '10'; }],
    ['different candidate artifact ID', () => { process.env.REQUIRED_CANDIDATE_ARTIFACT_ID = '12'; }],
    ['different SDK directory', f => { const other = join(f.localTemp, 'other-sdk'); mkdirSync(join(other, 'lib'), {recursive: true});
      writeFileSync(join(other, 'manifest.json'), fixtureSdk.manifestBytes); writeFileSync(join(other, 'lib', 'core.a'), sdkPayload);
      process.env.RSRS_CORE_SDK_DIR = other; }],
    ['changed candidate bytes', f => { writeFileSync(join(f.inputs, 'candidate.json'), readFileSync(join(f.inputs, 'candidate.json'), 'utf8') + '\n'); }],
    ['changed candidate with updated hash', f => { const bytes = Buffer.concat([readFileSync(join(f.inputs, 'candidate.json')), Buffer.from('\n')]);
      writeFileSync(join(f.inputs, 'candidate.json'), bytes); process.env.REQUIRED_CANDIDATE_SHA256 = sdkHash(bytes); }],
    ['changed retained candidate', f => { writeFileSync(join(f.raw, 'candidate.json'), '{}'); }],
    ['changed archive', f => { writeFileSync(join(f.inputs, 'sdk.tar.gz'), 'corrupt'); }],
    ['changed installed payload', f => { writeFileSync(join(f.sdkDir, 'lib', 'core.a'), 'corrupt'); }],
    ['changed manifest', f => { writeFileSync(join(f.sdkDir, 'manifest.json'), '{}'); }],
    ['missing hash', () => { delete process.env.REQUIRED_CANDIDATE_SHA256; }],
    ['extra input', f => { writeFileSync(join(f.inputs, 'extra.json'), '{}'); }],
    ['existing raw logs', f => { writeFileSync(join(f.raw, 'stdout.log'), sourceOutput); }],
    ['invalid preflight time', f => { const p = readJson(join(f.raw, 'preflight.json')); p.started_at = 'invalid'; writeJson(join(f.raw, 'preflight.json'), p); }],
  ]) rawCheck(`candidate capture refuses ${name} before spawn`, () => {
    const f = chainFixture(); prepare(); mutate(f); const before = spawnCalls;
    assert.throws(() => captureCoverage(coverageArgs)); assert.equal(spawnCalls, before);
  });
  for (const key of ['REQUIRED_CANDIDATE_RUN_ID', 'REQUIRED_CANDIDATE_ARTIFACT_ID']) {
    for (const value of ['', '0', '-1', '01', '1.2', '1e3', ' 9']) rawCheck(`prepare rejects ${key}=${JSON.stringify(value)}`, () => {
      chainFixture(); process.env[key] = value; assert.throws(prepare, /positive integer strings/);
    });
  }
  rawCheck('prepare cannot promote old raw', () => {
    const f = chainFixture(); mkdirSync(f.raw); writeFileSync(join(f.raw, 'stdout.log'), sourceOutput);
    assert.throws(prepare, /existing raw cannot be promoted/);
  });
  for (const [name, mutate] of [
    ['changed preflight bytes', f => { writeFileSync(join(f.raw, 'preflight.json'), readFileSync(join(f.raw, 'preflight.json'), 'utf8') + '\n'); }],
    ['changed candidate bytes', f => { writeFileSync(join(f.inputs, 'candidate.json'), '{}'); }],
    ['changed input ID', () => { process.env.REQUIRED_CANDIDATE_ARTIFACT_ID = '12'; }],
    ['changed SDK', f => { writeFileSync(join(f.sdkDir, 'lib', 'core.a'), 'corrupt'); }],
    ['changed logs', f => { writeFileSync(join(f.raw, 'stderr.log'), 'changed'); }],
    ['raw mode', f => { const e = readJson(join(f.raw, 'execution.json')); e.evidence_class = 'source-raw'; e.candidate_sha256 = null; e.actual_native_sdk = null; writeJson(join(f.raw, 'execution.json'), e); }],
    ['execution before prepare', f => { const e = readJson(join(f.raw, 'execution.json')); e.started_at = '2000-01-01T00:00:00.000Z'; writeJson(join(f.raw, 'execution.json'), e); }],
    ['failed execution', f => { const e = readJson(join(f.raw, 'execution.json')); e.exit_code = 1; writeJson(join(f.raw, 'execution.json'), e); }],
  ]) rawCheck(`produce refuses ${name}`, () => {
    const f = chainFixture(); prepare(); captureCoverage(coverageArgs); mutate(f); assert.throws(produce);
  });
  for (const value of ['', '0', '-1', '01', '1e3', '1.5', '9007199254740992']) rawCheck(`produce rejects raw artifact ID ${JSON.stringify(value)}`, () => {
    chainFixture(); prepare(); captureCoverage(coverageArgs); process.env.REQUIRED_RAW_ARTIFACT_ID = value;
    assert.throws(produce, /artifact ID/);
  });
  rawCheck('buildReports rejects malformed evidence independently', () => {
    const f = chainFixture(); prepare(); captureCoverage(coverageArgs);
    const p = readJson(join(f.raw, 'preflight.json')), e = readJson(join(f.raw, 'execution.json'));
    const out = readFileSync(join(f.raw, 'stdout.log')), err = readFileSync(join(f.raw, 'stderr.log'));
    const context = runContext(process.env);
    assert.equal(buildReports(context, p, e, out, err, 31).length, 2);
    for (const mutate of [
      v => { v.c.target = 'other'; }, v => { v.c.run_attempt = '0'; },
      v => { v.p.actual_native_sdk.extra = 'invalid'; v.e.actual_native_sdk.extra = 'invalid'; },
      v => { v.p.actual_native_sdk.version = ''; v.e.actual_native_sdk.version = ''; },
      v => { v.e.schema = 2; }, v => { v.p.schema = 1; },
      v => { v.e.gate = 'G1'; }, v => { v.e.evidence_class = 'source-raw'; },
      v => { v.e.actual_native_sdk = null; }, v => { v.e.candidate_run_id = '10'; },
      v => { v.e.preflight_sha256 = '0'.repeat(64); },
      v => { v.e.command.push('--release'); }, v => { v.e.command.push('--test', 'fixture'); },
      v => { v.e.command.push('--test', '../unsafe'); }, v => { v.e.command[1] = 'test'; },
      v => { v.e.completed_at = '2000-01-01T00:00:00.000Z'; },
      v => { v.e.completed_at = '2999-01-01T00:00:00.000Z'; },
      v => { v.e.started_at = 'invalid'; }, v => { v.e.exit_code = null; },
      v => { v.e.exit_code = 1; }, v => { v.e.signal = 'SIGTERM'; }, v => { v.e.error = 'ENOENT'; },
      v => { v.out = Buffer.alloc(0); v.e.stdout_sha256 = sdkHash(v.out); },
      v => { v.out = Buffer.from(sourceOutput.replace('running 2', 'running 3')); v.e.stdout_sha256 = sdkHash(v.out); },
    ]) {
      const v = {c: structuredClone(context), p: structuredClone(p), e: structuredClone(e), out, err}; mutate(v);
      assert.throws(() => buildReports(v.c, v.p, v.e, v.out, v.err, 31));
    }
  });
} finally {
  process.chdir(originalCwd); childProcess.spawnSync = originalSpawn; syncBuiltinESMExports();
  for (const [key, value] of Object.entries(originalEnv)) {
    if (value === undefined) delete process.env[key]; else process.env[key] = value;
  }
}
console.log(`Raw/candidate self-check passed: ${rawChecks} pure checks; synthetic evidence is not G1 acceptance`);
