#!/usr/bin/env node
// Offline publication tests. All registry reads and every npm publish are mocked.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {test} from 'node:test';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {assertTagSafe, checkPackage, compareVersions, packPackage, publishPackage,
  readExpectedPacks, waitForPackage} from './registry-publication.mjs';

const bytes = Buffer.from('a deterministic packed package for offline tests');
const digest = body => ({integrity: `sha512-${createHash('sha512').update(body).digest('base64')}`,
  shasum: createHash('sha1').update(body).digest('hex')});
const expected = {name: '@rsrsai/cli', version: '1.0.12-dev.9', filename: 'rsrsai-cli-1.0.12-dev.9.tgz', ...digest(bytes)};
const metadata = (overrides = {}) => ({name: expected.name, version: expected.version,
  dist: {...digest(bytes), tarball: 'https://registry.npmjs.org/@rsrsai/cli/-/cli-1.0.12-dev.9.tgz'}, ...overrides});
const json = data => new Response(JSON.stringify(data), {status: 200, headers: {'Content-Type': 'application/json'}});
const missing = () => new Response('', {status: 404});

function fixture(t) {
  const root = mkdtempSync(path.join(tmpdir(), 'rsrs-registry-test-'));
  t.after(() => rmSync(root, {recursive: true, force: true}));
  const dir = path.join(root, 'package');
  mkdirSync(dir);
  writeFileSync(path.join(dir, 'package.json'), JSON.stringify({name: expected.name, version: expected.version}));
  return {root, dir};
}

function mockNpm({publishStatus = 0, packBytes = bytes, packReport = expected, packOutput = report => [report], onPublish} = {}) {
  const calls = [];
  return {calls, spawnImpl(command, args, options) {
    calls.push({command, args, options});
    if (args[0] === 'pack') {
      assert(args.includes('--ignore-scripts'));
      const dest = args[args.indexOf('--pack-destination') + 1];
      writeFileSync(path.join(dest, packReport.filename), packBytes);
      return {status: 0, stdout: JSON.stringify(packOutput(packReport))};
    }
    assert.equal(args[0], 'publish');
    assert.equal(args.at(-1), 'https://registry.npmjs.org');
    assert.deepEqual(readFileSync(args[1]), bytes);
    onPublish?.();
    return {status: publishStatus};
  }};
}

function registry({absent = 0, tags = {dev: '1.0.12-dev.8'}, body = bytes, meta = metadata()} = {}) {
  const calls = [];
  let checked = 0;
  return {calls, async fetchImpl(url, options) {
    calls.push({url, options});
    assert.equal(options.credentials, 'omit');
    assert.equal(options.redirect, 'error');
    assert.equal(options.headers.Authorization, undefined);
    assert.equal(options.headers.authorization, undefined);
    if (url.includes('/dist-tags')) return tags === null ? missing() : json(tags);
    if (url.endsWith('.tgz')) return new Response(body);
    return checked++ < absent ? missing() : json(meta);
  }};
}

function fastClock() {
  let elapsed = 0;
  return {timeoutMs: 30, pollMs: 10, now: () => elapsed, sleep: async ms => {elapsed += ms;}};
}

test('exact metadata and downloaded sha512/sha1 match', async () => {
  assert.equal((await checkPackage(expected, registry())).version, expected.version);
});

test('404 may become visible within the bounded propagation wait', async () => {
  const mock = registry({absent: 2});
  assert.equal((await waitForPackage(expected, {...mock, ...fastClock()})).name, expected.name);
  assert.equal(mock.calls.filter(call => !call.url.endsWith('.tgz')).length, 3);
});

test('only HTTP 404 is absence; errors and invalid identity fail closed', async () => {
  for (const status of [401, 403, 429, 500, 503]) {
    await assert.rejects(checkPackage(expected, {fetchImpl: async () => new Response('', {status})}), /Registry HTTP/);
  }
  await assert.rejects(checkPackage(expected, {fetchImpl: async () => {throw new Error('network failed');}}), /network failed/);
  assert.equal(await checkPackage(expected, {fetchImpl: async () => missing()}), null);
  await assert.rejects(checkPackage(expected, registry({meta: metadata({name: 'wrong-package'})})), /identity mismatch/);
});

test('same version with different metadata hashes fails without fetching tarball', async () => {
  for (const field of ['integrity', 'shasum']) {
    const meta = metadata();
    meta.dist[field] = digest(Buffer.from('different content'))[field];
    const mock = registry({meta});
    await assert.rejects(checkPackage(expected, mock), /mismatch/);
    assert.equal(mock.calls.length, 1);
  }
});

test('metadata match cannot conceal different downloaded bytes', async () => {
  await assert.rejects(checkPackage(expected, registry({body: Buffer.from('tampered')})), /mismatch/);
});

test('missing tarball waits for propagation instead of declaring version absent', async () => {
  let reads = 0;
  const fetchImpl = async url => url.endsWith('.tgz')
    ? reads++ === 0 ? missing() : new Response(bytes) : json(metadata());
  await waitForPackage(expected, {fetchImpl, ...fastClock()});
  assert.equal(reads, 2);
});

test('tarball URL is HTTPS npm only, without credentials, queries, or redirects', async () => {
  for (const tarball of ['http://registry.npmjs.org/a.tgz', 'https://evil.invalid/a.tgz',
    'https://registry.npmjs.org.evil.invalid/a.tgz', 'https://user:secret@registry.npmjs.org/a.tgz',
    'https://registry.npmjs.org/a.tgz?token=secret', 'https://registry.npmjs.org:444/a.tgz']) {
    const meta = metadata(); meta.dist.tarball = tarball;
    const mock = registry({meta});
    await assert.rejects(checkPackage(expected, mock), /Unsafe registry URL/);
    assert.equal(mock.calls.length, 1);
  }
  const response = json(metadata());
  Object.defineProperty(response, 'url', {value: 'https://other.example/metadata'});
  await assert.rejects(checkPackage(expected, {fetchImpl: async () => response}), /Unsafe registry URL/);
});

test('short alias dependency must point to exact scoped version', async () => {
  const pinned = {...expected, dependencies: {'@rsrsai/cli': expected.version}};
  await checkPackage(pinned, registry({meta: metadata({dependencies: pinned.dependencies})}));
  await assert.rejects(checkPackage(pinned, registry({meta: metadata({dependencies: {'@rsrsai/cli': '^1.0.12'}})})), /dependencies mismatch/);
  await assert.rejects(checkPackage(pinned, registry({meta: metadata({dependencies: {...pinned.dependencies, extra: '*'}})})), /dependencies mismatch/);
});

test('existing identical package skips publish and makes no tag read/change', async t => {
  const {dir} = fixture(t), npm = mockNpm(), mock = registry({tags: {dev: '1.0.12-dev.99'}});
  const result = await publishPackage(dir, expected, 'dev', {...npm, ...mock});
  assert.equal(result.status, 'existing');
  assert.equal(npm.calls.length, 1);
  assert(!mock.calls.some(call => call.url.includes('/dist-tags')));
});

test('missing package publishes checked tarball exactly once, then waits', async t => {
  const {dir} = fixture(t), npm = mockNpm(), mock = registry({absent: 3});
  const result = await publishPackage(dir, expected, 'dev', {...npm, ...mock, ...fastClock()});
  assert.equal(result.status, 'published');
  assert.equal(npm.calls.filter(call => call.args[0] === 'publish').length, 1);
});

test('uncertain publish failure recovers only via matching registry bytes, never republish', async t => {
  const {dir} = fixture(t), npm = mockNpm({publishStatus: 1}), mock = registry({absent: 2});
  const result = await publishPackage(dir, expected, 'dev', {...npm, ...mock, ...fastClock()});
  assert.equal(result.status, 'recovered');
  assert.equal(npm.calls.filter(call => call.args[0] === 'publish').length, 1);
});

test('uncertain publish never reattempts after propagation timeout or different content', async t => {
  const {dir} = fixture(t);
  for (const mock of [registry({absent: Infinity}), registry({absent: 1, body: Buffer.from('wrong')})]) {
    const npm = mockNpm({publishStatus: 1});
    await assert.rejects(publishPackage(dir, expected, 'dev', {...npm, ...mock, ...fastClock()}), /failed or was uncertain/);
    assert.equal(npm.calls.filter(call => call.args[0] === 'publish').length, 1);
  }
});

test('registry permission/network error never triggers npm publish', async t => {
  const {dir} = fixture(t);
  for (const fetchImpl of [async () => new Response('', {status: 403}), async () => {throw new Error('offline');}]) {
    const npm = mockNpm();
    await assert.rejects(publishPackage(dir, expected, 'dev', {...npm, fetchImpl}));
    assert.equal(npm.calls.filter(call => call.args[0] === 'publish').length, 0);
  }
});

test('tag rollback is blocked including dev.10 versus dev.9; DEV cannot touch latest', async t => {
  assert(compareVersions('1.0.12-dev.10', '1.0.12-dev.9') > 0);
  assert(compareVersions('1.0.12', '1.0.12-dev.99') > 0);
  assert(compareVersions('1.0.12-dev.9', '1.0.13-dev.1') < 0);
  const {dir} = fixture(t), npm = mockNpm();
  await assert.rejects(publishPackage(dir, expected, 'dev', {...npm, ...registry({absent: 1, tags: {dev: '1.0.12-dev.10'}})}), /rollback/);
  assert.equal(npm.calls.filter(call => call.args[0] === 'publish').length, 0);
  await assert.rejects(publishPackage(dir, expected, 'latest', npm), /dev version under latest/);
  await assertTagSafe(expected, 'dev', registry({tags: null}));
  await assert.rejects(assertTagSafe(expected, 'dev', registry({tags: {dev: 'not-semver'}})), /safely compare/);
});

test('local package bytes must still match validated receipt before any registry request', async t => {
  const {dir} = fixture(t), other = Buffer.from('modified package');
  const npm = mockNpm({packBytes: other, packReport: {...expected, ...digest(other)}});
  let requests = 0;
  await assert.rejects(publishPackage(dir, expected, 'dev', {...npm, fetchImpl: async () => {requests++; return missing();}}), /mismatch/);
  assert.equal(requests, 0);
});

test('pack report hashes are verified against bytes on disk', t => {
  const {root, dir} = fixture(t);
  assert.throws(() => packPackage(dir, path.join(root, 'packs'), mockNpm({packBytes: Buffer.from('bad archive')})), /mismatch/);
});

test('all manifest receipts required, identity checked, platform ordering preserved', t => {
  const {root} = fixture(t), targets = ['@rsrsai/linux', '@rsrsai/macos'];
  const manifest = {cliVersion: expected.version, npmScope: expected.name, targets: targets.map(pkg => ({pkg}))};
  for (const name of [...targets, expected.name]) {
    const dir = path.join(root, name);
    mkdirSync(dir, {recursive: true});
    writeFileSync(path.join(dir, 'package.json'), JSON.stringify({name, version: expected.version}));
    writeFileSync(path.join(dir, 'release.pack.json'), JSON.stringify([{...expected, name}]));
  }
  assert.deepEqual(readExpectedPacks(root, manifest).map(item => item.name), [...targets, expected.name]);
  const receipt = path.join(root, targets[0], 'release.pack.json');
  writeFileSync(receipt, JSON.stringify([{...expected, name: targets[0], version: '0.0.0'}]));
  assert.throws(() => readExpectedPacks(root, manifest), /identity mismatch/);
  rmSync(receipt);
  assert.throws(() => readExpectedPacks(root, manifest), /ENOENT/);
});


test('tarballs are hashed as chunks without buffering the whole response', async () => {
  let streamed = false;
  const fetchImpl = async url => {
    if (!url.endsWith('.tgz')) return json(metadata());
    return {status: 200, body: (async function* () {
      streamed = true;
      yield bytes.subarray(0, 5); yield bytes.subarray(5);
    })(), arrayBuffer() {throw new Error('Whole response must not be buffered');}};
  };
  await checkPackage(expected, {fetchImpl});
  assert(streamed);
  await assert.rejects(checkPackage(expected, {...registry(), maxTarballBytes: 1}), /size limit/);
});

test('already visible metadata with delayed tarball cannot trigger publication', async t => {
  const {dir} = fixture(t), npm = mockNpm();
  let tarballs = 0;
  const fetchImpl = async url => url.endsWith('.tgz')
    ? tarballs++ === 0 ? missing() : new Response(bytes) : json(metadata());
  const result = await publishPackage(dir, expected, 'dev', {...npm, fetchImpl, ...fastClock()});
  assert.equal(result.status, 'existing');
  assert.equal(npm.calls.filter(call => call.args[0] === 'publish').length, 0);
});

test('missing verified receipt blocks pack --publish without clearing dist', t => {
  const {root} = fixture(t);
  const name = '@rsrsai/fixture';
  mkdirSync(path.join(root, 'cli'));
  mkdirSync(path.join(root, 'npm/dist', name), {recursive: true});
  writeFileSync(path.join(root, 'cli/Cargo.toml'), 'version = "1.0.0"\n');
  writeFileSync(path.join(root, 'npm/artifact-manifest.json'), JSON.stringify({cliVersion: '1.0.0', npmScope: name, targets: []}));
  writeFileSync(path.join(root, 'npm/dist', name, 'package.json'), JSON.stringify({name, version: '1.0.0'}));
  const sentinel = path.join(root, 'npm/dist', 'verified-evidence.txt');
  writeFileSync(sentinel, 'must survive publication');
  const script = fileURLToPath(new URL('./pack.mjs', import.meta.url));
  const result = spawnSync(process.execPath, [script, '--repo', root, '--publish'], {encoding: 'utf8'});
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /release.pack.json/);
  assert.equal(readFileSync(sentinel, 'utf8'), 'must survive publication');
});

test('real npm dry-run receipt matches actual tarball without publishing', t => {
  const {root, dir} = fixture(t);
  writeFileSync(path.join(dir, 'package.json'), JSON.stringify({...expected, files: ['cli.js']}));
  writeFileSync(path.join(dir, 'cli.js'), 'console.log("offline fixture");\n');
  const env = {...process.env, npm_config_cache: path.join(root, 'cache')};
  const spawnImpl = (command, args, options) => {
    assert.equal(args[0], 'pack', 'This test never permits npm publish');
    return spawnSync(command, args, {...options, env});
  };
  const command = process.platform === 'win32' ? 'npm.cmd' : 'npm';
  const dry = spawnImpl(command, ['pack', '--json', '--dry-run'], {cwd: dir, encoding: 'utf8', shell: process.platform === 'win32'});
  assert.equal(dry.status, 0, dry.stderr);
  const receipt = JSON.parse(dry.stdout)[0];
  writeFileSync(path.join(dir, 'release.pack.json'), JSON.stringify([receipt]));
  const actual = packPackage(dir, path.join(root, 'packs'), {spawnImpl});
  assert.equal(actual.integrity, receipt.integrity);
  assert.equal(actual.shasum, receipt.shasum);
});

test('npm 12 object-keyed pack output preserves identity and tarball checks', async t => {
  const f = fixture(t);
  const mock = mockNpm({packOutput: report => ({[report.name]: report})});
  const packed = packPackage(f.dir, f.root, mock);
  assert.equal(packed.integrity, expected.integrity);
  const result = await publishPackage(f.dir, expected, 'dev', {...mock, ...registry()});
  assert.equal(result.status, 'existing');
  assert.equal(mock.calls.filter(call => call.args[0] === 'publish').length, 0);
});
test('invalid npm JSON output shapes keep the identity-mismatch error', t => {
  const f = fixture(t);
  for (const raw of [null, true, 'bad', {}, expected, [null], {bad: null}, {wrong: expected}, {a: expected, b: expected}]) {
    assert.throws(() => packPackage(f.dir, f.root, mockNpm({packOutput: () => raw})), /npm pack report identity mismatch/);
  }
});
