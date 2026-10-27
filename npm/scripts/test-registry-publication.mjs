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
import {assertTagSafe, checkPackage, compareVersions, packPackage, publishPackage, publishAcceptedPackage,
  readExpectedPacks, waitForPackage, PackageNotVisibleError} from './registry-publication.mjs';

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
  let cancelled = 0;
  const transientStatuses = [408, 429, 500, 502, 503, 504];
  for (const failure of [
    () => {throw new DOMException('request timed out', 'TimeoutError');},
    () => {throw new TypeError('fetch failed', {cause: {code: 'ECONNRESET'}});},
    () => {throw Object.assign(new Error('body stalled'), {code: 'UND_ERR_BODY_TIMEOUT'});},
    ...transientStatuses.map(status => () => ({status, body: {cancel: async () => {cancelled++;}}})),
  ]) {
    const mock = registry();
    let attempts = 0;
    const fetchImpl = (url, options) => attempts++ === 0 ? failure() : mock.fetchImpl(url, options);
    assert.equal((await waitForPackage(expected, {...fastClock(), fetchImpl})).name, expected.name);
    assert.equal(attempts, 3, 'retry metadata, then verify matching tarball');
    let polls = 0;
    await assert.rejects(waitForPackage(expected, {...fastClock(), fetchImpl: () => {polls++; return failure();}}), /timed out/);
    assert.equal(polls, 4, 'temporary failures retain the original total deadline');
  }
  assert.equal(cancelled, transientStatuses.length * 5, 'every transient HTTP response releases its unread body');
});

test('only HTTP 404 is absence; errors and invalid identity fail closed', async () => {
  for (const status of [401, 403, 429, 500, 503]) {
    await assert.rejects(checkPackage(expected, {fetchImpl: async () => new Response('', {status})}), /Registry HTTP/);
  }
  await assert.rejects(checkPackage(expected, {fetchImpl: async () => {throw new Error('network failed');}}), /network failed/);
  assert.equal(await checkPackage(expected, {fetchImpl: async () => missing()}), null);
  await assert.rejects(checkPackage(expected, registry({meta: metadata({name: 'wrong-package'})})), /identity mismatch/);
  for (const fetchImpl of [
    async () => new Response('', {status: 401}),
    async () => new Response('', {status: 403}),
    async () => {throw new TypeError('fetch failed', {cause: {code: 'CERT_HAS_EXPIRED'}});},
    async () => {throw new TypeError('fetch failed', {cause: {code: 'ENOTFOUND'}});},
    async () => {throw new TypeError('fetch failed', {cause: {code: 'UND_ERR_REDIRECT'}});},
    async () => new Response('invalid JSON'),
  ]) {
    let attempts = 0;
    await assert.rejects(waitForPackage(expected, {...fastClock(), fetchImpl: (...args) => {attempts++; return fetchImpl(...args);}}));
    assert.equal(attempts, 1, 'authentication, TLS, configuration and malformed metadata are not retried');
  }
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
  const flaky = registry();
  let reads = 0;
  const resultAfterTimeout = await publishPackage(dir, expected, 'dev', {...npm, ...fastClock(),
    fetchImpl: (url, options) => {
      if (reads++ === 0) throw new DOMException('preflight timed out', 'TimeoutError');
      return flaky.fetchImpl(url, options);
    }});
  assert.equal(resultAfterTimeout.status, 'existing');
  assert.equal(npm.calls.filter(call => call.args[0] === 'publish').length, 0);
});

test('missing package publishes checked tarball exactly once, then waits', async t => {
  const {dir} = fixture(t), npm = mockNpm(), mock = registry({absent: 3});
  const result = await publishPackage(dir, expected, 'dev', {...npm, ...mock, ...fastClock()});
  assert.equal(result.status, 'published');
  assert.equal(npm.calls.filter(call => call.args[0] === 'publish').length, 1);
  for (const publishStatus of [0, 1]) {
    let submitted = false, interrupted = false;
    const npm = mockNpm({publishStatus, onPublish: () => {submitted = true;}});
    const mock = registry({absent: 1});
    const fetchImpl = (url, options) => {
      if (submitted && !interrupted) {
        interrupted = true;
        throw new DOMException('accepted submission read timed out', 'TimeoutError');
      }
      return mock.fetchImpl(url, options);
    };
    const result = await publishPackage(dir, expected, 'dev', {...npm, fetchImpl, ...fastClock()});
    assert.equal(result.status, publishStatus === 0 ? 'published' : 'recovered');
    assert.equal(npm.calls.filter(call => call.args[0] === 'publish').length, 1);
  }
  const delayedTag = registry({absent: 1});
  let tagFailed = false;
  const tagNpm = mockNpm();
  await publishPackage(dir, expected, 'dev', {...tagNpm, ...fastClock(), fetchImpl: (url, options) => {
    if (url.endsWith('/dist-tags') && !tagFailed) {
      tagFailed = true;
      throw new DOMException('tag read timed out', 'TimeoutError');
    }
    return delayedTag.fetchImpl(url, options);
  }});
  assert(tagFailed);
  assert.equal(tagNpm.calls.filter(call => call.args[0] === 'publish').length, 1);
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
  const clock = fastClock(), mock = registry({absent: 1});
  let preflightFailed = false, tagFailed = false, submitted = false;
  const npm = mockNpm({onPublish: () => {submitted = true;}});
  await assert.rejects(publishPackage(dir, expected, 'dev', {...npm, ...clock, fetchImpl: (url, options) => {
    if (submitted) throw new DOMException('confirmation timeout', 'TimeoutError');
    if (url.endsWith('/dist-tags')) {
      if (!tagFailed) {tagFailed = true; throw new DOMException('tag timeout', 'TimeoutError');}
    } else if (!preflightFailed) {preflightFailed = true; throw new DOMException('preflight timeout', 'TimeoutError');}
    return mock.fetchImpl(url, options);
  }}), /timed out/);
  assert.equal(clock.now(), clock.timeoutMs, 'all read stages share one deadline');
  assert.equal(npm.calls.filter(call => call.args[0] === 'publish').length, 1);
});

test('registry permission/network error never triggers npm publish', async t => {
  const {dir} = fixture(t);
  for (const fetchImpl of [async () => new Response('', {status: 403}), async () => {throw new Error('offline');}]) {
    const npm = mockNpm();
    await assert.rejects(publishPackage(dir, expected, 'dev', {...npm, fetchImpl}));
    assert.equal(npm.calls.filter(call => call.args[0] === 'publish').length, 0);
  }
  const npm = mockNpm();
  let polls = 0;
  await assert.rejects(publishPackage(dir, expected, 'dev', {...npm, ...fastClock(), fetchImpl: async () => {
    polls++;
    throw new DOMException('preflight permanently stalled', 'TimeoutError');
  }}), /timed out/);
  assert.equal(polls, 4);
  assert.equal(npm.calls.filter(call => call.args[0] === 'publish').length, 0);
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
  let tarballs = 0;
  await waitForPackage(expected, {...fastClock(), fetchImpl: async url => {
    if (!url.endsWith('.tgz')) return json(metadata());
    const attempt = ++tarballs;
    return {status: 200, body: (async function* () {
      yield bytes.subarray(0, 5);
      if (attempt === 1) throw new DOMException('stream timed out', 'TimeoutError');
      yield bytes.subarray(5);
    })()};
  }});
  assert.equal(tarballs, 2, 'partial failed downloads restart both hash accumulators');
});

test('already visible metadata with delayed tarball cannot trigger publication', async t => {
  const {dir} = fixture(t), npm = mockNpm();
  let tarballs = 0;
  const fetchImpl = async url => url.endsWith('.tgz')
    ? tarballs++ === 0 ? missing() : new Response(bytes) : json(metadata());
  const result = await publishPackage(dir, expected, 'dev', {...npm, fetchImpl, ...fastClock()});
  assert.equal(result.status, 'existing');
  assert.equal(npm.calls.filter(call => call.args[0] === 'publish').length, 0);
  const exactUrl = `https://registry.npmjs.org/${encodeURIComponent(expected.name)}/${expected.version}`;
  const indexUrl = `https://registry.npmjs.org/${encodeURIComponent(expected.name)}`;
  for (const pendingAt of ['tarball-404', 'tarball-timeout', 'index-404', 'index-timeout', 'metadata-body-timeout']) {
    for (const recovers of [true, false]) {
      const npm = mockNpm(), clock = fastClock();
      let exactReads = 0, interrupted = false;
      const fetchImpl = async url => {
        if (url === exactUrl) {
          exactReads++;
          if (exactReads > 1 && (!recovers || exactReads === 2)) return missing();
          if (pendingAt === 'metadata-body-timeout' && !interrupted) {
            interrupted = true;
            return {status: 200, json: async () => {throw new DOMException('metadata body timed out', 'TimeoutError');}};
          }
          return json(metadata());
        }
        if (!interrupted && ((url.endsWith('.tgz') && pendingAt.startsWith('tarball'))
            || (url === indexUrl && pendingAt.startsWith('index')))) {
          interrupted = true;
          if (pendingAt.endsWith('timeout')) throw new DOMException('propagation read timed out', 'TimeoutError');
          return missing();
        }
        if (url === indexUrl) return json({name: expected.name, versions: {[expected.version]: metadata()}});
        if (url.endsWith('/dist-tags')) return json({});
        assert(url.endsWith('.tgz'));
        return new Response(bytes);
      };
      const publication = publishPackage(dir, expected, 'dev', {...npm, ...clock, fetchImpl, requireInstallIndex: true});
      const result = recovers ? await publication : await assert.rejects(publication, /timed out/);
      assert(interrupted);
      assert.equal(npm.calls.filter(c => c.args[0] === 'publish').length, 0, `${pendingAt} then metadata404 must never submit`);
      if (recovers) assert.equal(result.status, 'existing');
    }
  }
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
  assert.equal(dry.error, undefined, dry.error?.message);
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


function installRegistry({absent = 0, pending = 0, index404 = 0, index = metadata(), body = bytes, indexStatus = 200} = {}) {
  let exactReads = 0, indexReads = 0;
  const calls = [];
  const root = `https://registry.npmjs.org/${encodeURIComponent(expected.name)}`;
  return {calls, async fetchImpl(url, options) {
    calls.push({url, options});
    assert.equal(options.credentials, 'omit');
    assert.equal(options.redirect, 'error');
    assert.equal(options.headers.Authorization, undefined);
    if (url.endsWith('/dist-tags')) return json({dev: '1.0.12-dev.8'});
    if (url.endsWith('.tgz')) return new Response(body);
    if (url === `${root}/${expected.version}`) return exactReads++ < absent ? missing() : json(metadata());
    assert.equal(url, root);
    assert.equal(options.headers.Accept, 'application/vnd.npm.install-v1+json');
    indexReads++;
    if (indexReads <= index404) return missing();
    if (indexStatus !== 200) return new Response('', {status: indexStatus});
    return json({name: expected.name, versions: indexReads <= pending ? {} : {[expected.version]: index}});
  }};
}

test('install index may lag exact metadata; wait finishes before downloading bytes once', async () => {
  for (const options of [{pending: 2}, {index404: 2}]) {
    const mock = installRegistry(options);
    const result = await waitForPackage(expected, {...mock, ...fastClock(), requireInstallIndex: true});
    assert.equal(result.version, expected.version);
    assert.equal(mock.calls.filter(c => c.options.headers.Accept.includes('install-v1')).length, 3);
    assert.equal(mock.calls.filter(c => c.url.endsWith('.tgz')).length, 1);
  }
  for (const failAt of ['metadata-json', 'index-fetch', 'index-json']) {
    const mock = installRegistry();
    let failed = false;
    const root = `https://registry.npmjs.org/${encodeURIComponent(expected.name)}`;
    await waitForPackage(expected, {...fastClock(), requireInstallIndex: true,
      fetchImpl: async (url, options) => {
        if (!failed && ((failAt.startsWith('index') && url === root)
            || (failAt === 'metadata-json' && url === `${root}/${expected.version}`))) {
          failed = true;
          if (failAt === 'index-fetch') throw new DOMException('index timed out', 'TimeoutError');
          return {status: 200, json: async () => {throw new DOMException('JSON body timed out', 'TimeoutError');}};
        }
        return mock.fetchImpl(url, options);
      }});
    assert(failed);
  }
});

test('a permanently absent install-index version times out without republishing an existing package', async t => {
  const {dir} = fixture(t), npm = mockNpm(), mock = installRegistry({pending: Infinity});
  await assert.rejects(publishPackage(dir, expected, 'dev', {
    ...npm, ...mock, ...fastClock(), requireInstallIndex: true,
  }), error => error instanceof PackageNotVisibleError && /timed out/.test(error.message));
  assert.equal(npm.calls.filter(c => c.args[0] === 'publish').length, 0);
  assert.equal(mock.calls.filter(c => c.url.endsWith('.tgz')).length, 0);
});

test('an accepted single publication waits for the install index and never resubmits', async t => {
  const {dir} = fixture(t), npm = mockNpm(), mock = installRegistry({absent: 1, pending: 2});
  const result = await publishPackage(dir, expected, 'dev', {
    ...npm, ...mock, ...fastClock(), requireInstallIndex: true,
  });
  assert.equal(result.status, 'published');
  assert.equal(npm.calls.filter(c => c.args[0] === 'publish').length, 1);
  assert.equal(mock.calls.filter(c => c.options.headers.Accept.includes('install-v1')).length, 3);
});

test('an abbreviated index may omit integrity but actual SHA512 bytes remain mandatory', async () => {
  const index = metadata(); delete index.dist.integrity;
  await checkPackage(expected, {...installRegistry({index}), requireInstallIndex: true});
  await assert.rejects(checkPackage(expected, {
    ...installRegistry({index, body: Buffer.from('tampered package')}), requireInstallIndex: true,
  }), /mismatch/);
});

test('provided install-index identity, digest and tarball conflicts fail before downloading', async () => {
  const bad = [
    m => m.name = 'wrong',
    m => m.version = '0.0.0',
    m => m.dist.shasum = '0'.repeat(40),
    m => m.dist.integrity = digest(Buffer.from('different')).integrity,
    m => m.dist.integrity = null,
    m => m.dist.tarball = 'https://registry.npmjs.org/other.tgz',
    m => m.dist.tarball = 'https://evil.invalid/other.tgz',
  ];
  for (const mutate of bad) {
    const index = metadata(); mutate(index);
    const mock = installRegistry({index});
    await assert.rejects(checkPackage(expected, {...mock, requireInstallIndex: true}), /mismatch|Unsafe registry URL|Missing or invalid pack/);
    assert.equal(mock.calls.filter(c => c.url.endsWith('.tgz')).length, 0);
  }
});

test('present malformed install dependency maps fail while absent and empty maps match', async () => {
  for (const field of ['dependencies', 'optionalDependencies']) {
    for (const value of [null, [], 'bad', 0, false]) {
      const index = metadata({[field]: value}), mock = installRegistry({index});
      await assert.rejects(checkPackage(expected, {...mock, requireInstallIndex: true}), /dependency map/);
      assert.equal(mock.calls.filter(c => c.url.endsWith('.tgz')).length, 0);
    }
    await checkPackage(expected, {...installRegistry({index: metadata({[field]: {}})}), requireInstallIndex: true});
    await assert.rejects(checkPackage(expected, {
      ...installRegistry({index: metadata({[field]: {extra: '*'}})}), requireInstallIndex: true,
    }), new RegExp(`install ${field} mismatch`));
  }
});

test('install-index HTTP and network errors are not treated as pending publication', async t => {
  const {dir} = fixture(t);
  for (const indexStatus of [401, 403, 429, 500, 503]) {
    const npm = mockNpm();
    await assert.rejects(publishPackage(dir, expected, 'dev', {
      ...npm, ...installRegistry({indexStatus}), ...fastClock(), requireInstallIndex: true,
    }), new RegExp(`Registry HTTP ${indexStatus}`));
    assert.equal(npm.calls.filter(c => c.args[0] === 'publish').length, 0);
  }
  const mock = installRegistry(), root = `https://registry.npmjs.org/${encodeURIComponent(expected.name)}`;
  let failures = 0;
  await assert.rejects(waitForPackage(expected, {
    ...fastClock(), requireInstallIndex: true,
    fetchImpl: async (url, options) => {
      if (url === root) {failures++; throw new Error('install-index connection failed');}
      return mock.fetchImpl(url, options);
    },
  }), /install-index connection failed/);
  assert.equal(failures, 1);
});

test('explicit npm acceptance does not wait for public propagation or claim verification', async t => {
  const {dir} = fixture(t), npm = mockNpm(), mock = registry({absent: Infinity});
  const intents = [];
  const result = await publishAcceptedPackage(dir, expected, 'dev', {...npm,...mock,...fastClock(),requireInstallIndex:true,
    onSubmission:event=>intents.push(event)});
  assert.equal(result.status,'published');
  assert.equal(result.acceptance.state,'accepted');
  assert.equal(result.acceptance.evidence,'npm-exit-zero');
  assert.equal(result.acceptance.integrity,expected.integrity);
  assert.equal(result.metadata,undefined);
  assert.equal(result.install,undefined);
  assert.equal(intents.length,1);
  assert.equal(intents[0].state,'unknown','intent is durable before the irreversible submission');
  assert.equal(mock.calls.length,2,'only preflight version and tag reads, never propagation/install reads');
  assert.equal(npm.calls.filter(c=>c.args[0]==='publish').length,1);
});

test('failed, signalled or spawn-error npm cannot be accepted from exit status alone', async t => {
  const {dir} = fixture(t);
  for(const outcome of [{status:1},{status:null,signal:'SIGTERM'},{status:0,error:new Error('EPERM')},{status:0,signal:'SIGTERM'}]) {
    const npm=mockNpm(), spawnImpl=(name,args,opts)=>args[0]==='publish'?(npm.calls.push({args}),outcome):npm.spawnImpl(name,args,opts);
    await assert.rejects(publishAcceptedPackage(dir,expected,'dev',{spawnImpl,...registry({absent:Infinity}),...fastClock()}),/failed or was uncertain/);
    assert.equal(npm.calls.filter(c=>c.args[0]==='publish').length,1,'uncertain submission is never repeated');
  }
});

test('uncertain acceptance can only be recovered by matching public content', async t => {
  const {dir}=fixture(t), npm=mockNpm({publishStatus:null});
  const result=await publishAcceptedPackage(dir,expected,'dev',{...npm,...registry({absent:1}),...fastClock()});
  assert.equal(result.status,'recovered');
  assert.equal(result.acceptance.evidence,'verified-public-bytes');
  assert.equal(result.metadata,undefined);
  assert.equal(npm.calls.filter(c=>c.args[0]==='publish').length,1);
});

test('durable prior acceptance prevents a second submission even while all public registry reads return 404',async t=>{
  const {dir}=fixture(t),npm=mockNpm();
  const prior={...expected,schema:1,state:'accepted',evidence:'npm-exit-zero',exit_code:0,signal:null,accepted_at:'2026-10-27T00:00:00Z'};
  const result=await publishAcceptedPackage(dir,expected,'dev',{...npm,knownAcceptances:[prior],fetchImpl:()=>assert.fail('prior acceptance does not wait for propagation')});
  assert.equal(result.status,'previously-accepted');assert.equal(result.acceptance,prior);
  assert.equal(npm.calls.filter(c=>c.args[0]==='publish').length,0);
  const bad={...prior,integrity:digest(Buffer.from('other')).integrity};
  await assert.rejects(publishAcceptedPackage(dir,expected,'dev',{...npm,knownAcceptances:[bad]}),/mismatch/);
});
