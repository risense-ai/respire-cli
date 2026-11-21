import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { readValidatedPacks } from '../npm/scripts/registry-publication.mjs';
import { verifyBinary } from '../npm/scripts/verify-binary.mjs';
import { verifyCandidate } from './produce-required-tests.mjs';

const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const read = path => JSON.parse(readFileSync(path, 'utf8'));
const [target, candidateFile, candidateHash, packDirectory, destination] = process.argv.slice(2);
assert.equal(process.argv.length, 7,
  'Usage: verify-candidate-npm.mjs TARGET CANDIDATE_JSON SHA256 PACK_DIRECTORY NEW_FIXTURE_DIRECTORY');

const manifest = read(new URL('../npm/artifact-manifest.json', import.meta.url));
assert.equal(manifest.artifactLayout, 'cli-frontend-v2');
const platform = manifest.targets.find(entry => entry.triple === target);
assert.ok(platform?.os.includes(process.platform) && platform.cpu.includes(process.arch),
  'Use a native runner for the selected package target');

const index = read(join(packDirectory, 'source-version.json'));
const producer = index.producer;
const source = {repository:'risense-ai/respire-cli', run_id:producer.run_id,
  run_attempt:producer.run_attempt, sha:producer.sha};
if (process.env.GITHUB_ACTIONS === 'true') {
  assert.equal(source.sha, process.env.GITHUB_SHA);
  assert.equal(source.run_id, process.env.PACKAGE_RUN_ID);
  assert.equal(String(source.run_attempt), process.env.PACKAGE_RUN_ATTEMPT);
}
const candidate = verifyCandidate(readFileSync(candidateFile), candidateHash, {source_sha:source.sha});
const cli = candidate.components.cli;
const expected = cli.artifacts[target];
assert.equal(expected?.native_sdk, null, 'Frontend target must exist and have an explicit null SDK');
const byName = new Map(readValidatedPacks(packDirectory, source, {...manifest, cliVersion:cli.version})
  .map(pack => [pack.name, pack]));
const launcherPack = byName.get(manifest.npmScope);
const platformPack = byName.get(platform.pkg);
assert.match(cli.launcher_archive_sha256, /^[a-f0-9]{64}$/, 'Freeze the launcher archive digest');
assert.equal(launcherPack.sha256, cli.launcher_archive_sha256);
assert.equal(platformPack.sha256, expected.archive_sha256);

const fixture = resolve(destination);
mkdirSync(fixture);
const profile = join(fixture, 'profile');
const home = join(fixture, 'home');
const temporary = join(fixture, 'tmp');
mkdirSync(home);
mkdirSync(temporary);
mkdirSync(join(profile, 'bin', 'runtime'), {recursive:true});
writeFileSync(join(fixture, 'package.json'), '{"private":true}\n', {flag:'wx'});
for (const [name, pack] of [['launcher.tgz', launcherPack], ['platform.tgz', platformPack]]) {
  const bytes = readFileSync(pack.tarballPath);
  assert.equal(bytes.length, pack.size);
  assert.equal(hash(bytes), pack.sha256);
  writeFileSync(join(fixture, name), bytes, {flag:'wx'});
}

// Use a fresh project and explicit prefix so npm cannot select a parent workspace.
const env = Object.fromEntries(Object.entries(process.env)
  .filter(([key]) => /^(path|pathext|systemroot|windir|comspec|systemdrive)$/i.test(key)));
Object.assign(env, {
  HOME:home, USERPROFILE:home, APPDATA:home, LOCALAPPDATA:home,
  TMP:temporary, TEMP:temporary, TMPDIR:temporary,
  npm_config_userconfig:join(fixture, 'user.npmrc'),
  npm_config_globalconfig:join(fixture, 'global.npmrc'),
  npm_config_cache:join(fixture, 'cache'),
  RSRS_DATA_DIR:profile, RSRS_UPDATE_CHECK:'0', RSRS_NO_AUTOSYNC:'1',
});
if (process.platform === 'linux') env.RSRS_LIBC = target.endsWith('-gnu') ? 'glibc' : 'musl';
const options = {cwd:fixture, env, encoding:'utf8', timeout:120000};
const windows = process.platform === 'win32';
function npm(args) {
  // Arguments are fixed literals. The fixture location travels through cwd.
  return windows
    ? execFileSync('cmd.exe', ['/d', '/c', 'npm.cmd', ...args], options)
    : execFileSync('npm', args, options);
}
assert.equal(realpathSync(npm(['--prefix', '.', 'prefix']).trim()), realpathSync(fixture));
npm(['--prefix', '.', 'install', '--offline', '--ignore-scripts', '--no-audit',
  '--no-fund', '--no-package-lock', './launcher.tgz', './platform.tgz']);

const modules = join(fixture, 'node_modules');
const installedPackage = join(modules, platform.pkg);
const installed = read(join(installedPackage, 'package.json'));
assert.deepEqual([installed.name, installed.version], [platform.pkg, cli.version]);
const binary = join(installedPackage, 'bin', windows ? 'rsrs.exe' : 'rsrs');
verifyBinary(binary, target);
const binaryDigest = hash(readFileSync(binary));
assert.equal(binaryDigest, expected.binary_sha256);
const launcher = join(modules, manifest.npmScope, 'bin', 'cli.js');
assert.equal(execFileSync(process.execPath, [launcher, '--version'], options).trim(), `rsrs ${cli.version}`);
const list = JSON.parse(execFileSync(process.execPath, [launcher, '--json', 'runtime', 'list'], options));
assert.equal(list.command, 'runtime.list');
assert.equal(list.status, 'ok');
assert.deepEqual(list.summary.installed, []);

const receipt = {schema:1, scope:'candidate-npm-native-install', status:'passed', target,
  source_sha:source.sha, version:cli.version, producer:source, candidate_sha256:candidateHash,
  platform_archive_sha256:platformPack.sha256, launcher_archive_sha256:launcherPack.sha256,
  installed_binary_sha256:binaryDigest,
  cases:['offline-install', 'native-launcher-version', 'isolated-runtime-inventory']};
writeFileSync(join(fixture, 'native-package-install.json'), JSON.stringify(receipt, null, 2)+'\n', {flag:'wx'});
console.log(`Verified native npm candidate install on ${target}`);
