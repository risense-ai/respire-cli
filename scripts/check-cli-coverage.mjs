import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
import {pathToFileURL} from 'node:url';

export function coveragePolicy(cargo, manifest, report, candidate = 'false') {
  assert(['true', 'false'].includes(candidate), 'invalid CANDIDATE_MODE');
  const pkg = cargo.match(/^\[package\]\s*\n([\s\S]*?)(?=^\[|(?![\s\S]))/m)?.[1];
  const versions = [...(pkg ?? '').matchAll(/^version\s*=\s*"([^"]+)"\s*$/gm)];
  assert.equal(versions.length, 1, 'one explicit package version required');
  const version = versions[0][1];
  const numeric = '(?:0|[1-9][0-9]*)';
  const identifier = '(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)';
  assert(new RegExp(`^${numeric}\\.${numeric}\\.${numeric}(?:-${identifier}(?:\\.${identifier})*)?(?:\\+[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*)?$`).test(version), 'unknown CLI version');
  assert.equal(manifest.cliVersion, version, 'Cargo/artifact CLI version mismatch');
  assert.equal(report.type, 'llvm.coverage.json.export');
  assert.equal(report.version, '3.1.0');
  assert(Array.isArray(report.data) && report.data.length === 1, 'one coverage dataset required');
  const lines = report.data[0]?.totals?.lines;
  assert(lines && Number.isSafeInteger(lines.count) && lines.count > 0, 'nonempty line count required');
  assert(Number.isSafeInteger(lines.covered) && lines.covered >= 0 && lines.covered <= lines.count, 'invalid covered count');
  const percent = 100 * lines.covered / lines.count;
  assert(Number.isFinite(lines.percent) && Math.abs(lines.percent - percent) < 0.01, 'inconsistent line percentage');
  const advisory = candidate === 'false' && new RegExp(`^${numeric}\\.${numeric}\\.${numeric}-dev\\.${numeric}$`).test(version);
  const below = BigInt(lines.covered) * 100n < BigInt(lines.count) * 90n;
  return {version, count: lines.count, covered: lines.covered, percent, advisory, below, pass: advisory || !below};
}

export function runCoverage({cargo, manifest, ignore, candidate = 'false', execute = execFileSync, log = console.log}) {
  assert(typeof ignore === 'string' && ignore.length > 0, 'coverage exclusions required');
  const args = ['llvm-cov', 'report', '-p', 'respire', '--ignore-filename-regex', ignore];
  // Tool failures are never interpreted as a low-coverage result, even for DEV.
  execute('cargo', [...args, '--show-missing-lines'], {stdio: 'inherit'});
  const report = JSON.parse(execute('cargo', [...args, '--json', '--summary-only'], {encoding: 'utf8', maxBuffer: 64 * 1024 * 1024}));
  const result = coveragePolicy(cargo, manifest, report, candidate);
  log(`CLI ${result.version}: ${result.covered}/${result.count} lines (${result.percent.toFixed(2)}%); 90% ${result.advisory ? 'DEV advisory' : 'required'}`);
  if (result.below && result.advisory) log('::warning::DEV coverage is below 90%; functional tests remain mandatory. Stable/non-DEV and frozen G1 candidates still require 90%.');
  assert(result.pass, 'CLI line coverage must be at least 90%');
  return result;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    assert.equal(process.argv.length, 3, 'usage: check-cli-coverage.mjs <unchanged-ignore-regex>');
    runCoverage({cargo: readFileSync('cli/Cargo.toml', 'utf8'), manifest: JSON.parse(readFileSync('npm/artifact-manifest.json', 'utf8')), ignore: process.argv[2], candidate: process.env.CANDIDATE_MODE ?? 'false'});
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
