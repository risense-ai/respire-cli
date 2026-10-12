// Offline only: no real registry, accounts, models, or npm subprocesses.
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, existsSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {publishScopedPackages} from './parallel-publication.mjs';
import {publishPackage} from './registry-publication.mjs';

const umbrella = '@rsrsai/cli';
const batch = Array.from({length: 5}, (_, i) => ({name: i === 4 ? umbrella : `@rsrsai/platform-${i}`,
  version: '1.0.12-dev.7', dir: `fixture-${i}`}));
const deferred = () => { let resolve; const promise = new Promise(r => {resolve = r;}); return {promise, resolve}; };

test('four bounded workers overlap; umbrella waits for the last verified platform', async () => {
  const gates = batch.slice(0, 4).map(deferred), started = [], finished = [];
  const run = publishScopedPackages(batch, umbrella, 'dev', {publishImpl: async (_, receipt) => {
    started.push(receipt.name);
    if (receipt.name !== umbrella) await gates[batch.indexOf(receipt)].promise;
    else assert.equal(finished.length, 4);
    finished.push(receipt.name);
    return {status: 'published'};
  }});
  assert.deepEqual(started, batch.slice(0, 4).map(r => r.name));
  for (const gate of gates.slice(0, 3)) gate.resolve();
  await new Promise(setImmediate);
  assert(!started.includes(umbrella));
  gates[3].resolve();
  assert.equal((await run).length, 5);
  assert.equal(started.at(-1), umbrella);
});

test('failure drains in-flight work and blocks umbrella; no queued publication starts', async () => {
  const gate = deferred(), started = [];
  const larger = [...batch.slice(0, 4), {name: '@rsrsai/extra', version: batch[0].version}, batch[4]];
  const run = publishScopedPackages(larger, umbrella, 'dev', {publishImpl: async (_, receipt) => {
    started.push(receipt.name);
    if (receipt.name === batch[0].name) throw new Error('hash mismatch');
    await gate.promise;
    return {status: 'existing'};
  }});
  let settled = false;
  const checked = assert.rejects(run, error => error instanceof AggregateError && error.errors[0].message === 'hash mismatch').then(() => {settled = true;});
  await new Promise(setImmediate);
  assert.equal(settled, false);
  gate.resolve(); await checked;
  assert.equal(started.length, 4);
  assert(!started.includes(umbrella));
});

test('duplicate, missing umbrella, empty platforms and mixed version fail before side effects', async () => {
  for (const receipts of [[...batch, batch[0]], batch.slice(0, 4), [batch[4]],
    batch.map((r, i) => i === 0 ? {...r, version: '1.0.12-dev.6'} : r)]) {
    await assert.rejects(publishScopedPackages(receipts, umbrella, 'dev', {publishImpl: () => assert.fail('must not publish')}));
  }
});

test('real helper preserves immutable receipts, unique temp files, existing skip and uncertain single submission', async t => {
  const root = mkdtempSync(path.join(tmpdir(), 'rsrs-parallel-test-'));
  t.after(() => rmSync(root, {recursive: true, force: true}));
  const receipts = batch.map((r, i) => {
    const dir = path.join(root, String(i)), bytes = Buffer.from(`synthetic artifact source ${i}`);
    mkdirSync(dir); writeFileSync(path.join(dir, 'package.json'), JSON.stringify(r));
    return {...r, dir, bytes, filename: 'same-name.tgz',
      integrity: `sha512-${createHash('sha512').update(bytes).digest('base64')}`,
      shasum: createHash('sha1').update(bytes).digest('hex')};
  });
  const tempPaths = [], submissions = new Map(), visible = new Set([receipts[0].name]);
  const verified = new Set(), barrier = deferred(); let active = 0, maxActive = 0;
  const publishImpl = async (dir, receipt, tag) => publishPackage(dir, receipt, tag, {
    timeoutMs: 1000, pollMs: 1,
    spawnImpl: (_, args) => {
      if (args[0] === 'pack') {
        const dest = args[args.indexOf('--pack-destination') + 1];
        const file = path.join(dest, receipt.filename); tempPaths.push(file);
        writeFileSync(file, receipt.bytes);
        return {status: 0, stdout: JSON.stringify([receipt])};
      }
      assert.deepEqual(readFileSync(args[1]), receipt.bytes);
      submissions.set(receipt.name, (submissions.get(receipt.name) || 0) + 1);
      visible.add(receipt.name);
      return {status: receipt === receipts[2] ? null : 0};
    },
    fetchImpl: async url => {
      if (url.includes('dist-tags')) return new Response('{}');
      if (!visible.has(receipt.name)) return new Response('', {status: 404});
      if (url.endsWith('.tgz')) {
        if (receipt.name !== umbrella) {
          active++; maxActive = Math.max(maxActive, active);
          if (active === 4) barrier.resolve();
          await barrier.promise; active--;
          verified.add(receipt.name);
        } else assert.equal(verified.size, 4);
        return new Response(receipt.bytes);
      }
      return new Response(JSON.stringify({name: receipt.name, version: receipt.version,
        dist: {integrity: receipt.integrity, shasum: receipt.shasum,
          tarball: `https://registry.npmjs.org/${receipt.name}/-/fixture.tgz`}}));
    },
  });
  const results = await publishScopedPackages(receipts, umbrella, 'dev', {publishImpl});
  assert.equal(maxActive, 4);
  assert.equal(results[0].status, 'existing');
  assert.equal(results[2].status, 'recovered');
  assert(!submissions.has(receipts[0].name));
  assert.deepEqual([...submissions.values()], [1, 1, 1, 1]);
  assert.equal(new Set(tempPaths).size, 5);
  assert(tempPaths.every(file => !existsSync(file)));
  // Rerun verifies every exact package and never submits again.
  await publishScopedPackages(receipts, umbrella, 'dev', {publishImpl});
  assert.deepEqual([...submissions.values()], [1, 1, 1, 1]);
});
