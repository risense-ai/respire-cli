import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync, readdirSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {PUBLICATION_MAX_BUFFER, publicationCommand, scopedPublisherFinished, selectRelease, validateArtifact, assertTagCommit, assertDraft, assertSourceRun, validateAlias, validateScoped, validateSource, readyName, aliasName} from './release-publication.mjs';

const m = JSON.parse(readFileSync(new URL('../artifact-manifest.json', import.meta.url)));
const integrity = 'sha512-' + createHash('sha512').update('synthetic package').digest('base64');
const hash = 'a'.repeat(64), sha = 'b'.repeat(40), version = '1.2.3-dev.4';
const source = {repository: 'risense-ai/respire-cli', workflow: '.github/workflows/release.yml', run_id: '100', run_attempt: '2', sha, version, channel: 'dev', release_id: 300};
const sourceRun = {id: 100, run_attempt: 2, path: source.workflow, head_repository: {full_name: source.repository}, event: 'workflow_dispatch', head_sha: 'c'.repeat(40), status: 'in_progress'};
const scoped = {schema: 1, kind: 'scoped-ready', source,
  packages: [...m.targets.map(t => t.pkg), m.npmScope].map(name => ({name, version, integrity, shasum: 'd'.repeat(40)})),
  binaries: m.targets.map(t => ({package: t.pkg, target: t.triple, file: `rsrs-${t.triple}${t.triple.includes('windows') ? '.exe' : ''}`, sha256: hash})),
  assets: m.targets.flatMap(t => [`cli-build-${t.triple}.json`, `rsrs-${t.triple}-runtime.tar.gz`, `rsrs-${t.triple}${t.triple.includes('windows') ? '.exe' : ''}`]).sort().map(name => ({name, size: 42, sha256: hash})),
};
const aliasRun = {id: 400, run_attempt: 3, path: '.github/workflows/npm-alias.yml', event: 'workflow_run', head_repository: {full_name: source.repository}, status: 'completed', conclusion: 'success'};
const alias = {schema: 1, kind: 'alias-ready', source, scoped_packages: scoped.packages,
  alias: {name: 'rsrs-cli', version, integrity, shasum: 'd'.repeat(40)},
  publisher: {workflow: aliasRun.path, run_id: '400', run_attempt: '3'},
  install: {platform: 'linux-x64-gnu', version, binary_sha256: hash}};
const jobs = [{name: 'publish-integrated', conclusion: 'success'}];
const release = {id: 300, draft: true, tag_name: `v${version}`, target_commitish: sha, prerelease: true,
  assets: scoped.assets.map(a => ({name: a.name, size: a.size, state: 'uploaded', digest: `sha256:${a.sha256}`}))};
const copy = value => structuredClone(value);

test('complete ordinary and recovery job inventories wait only for the selected publisher', () => {
  const workflow = readFileSync(new URL('../../.github/workflows/release.yml', import.meta.url), 'utf8').replace(/\r\n/g, '\n');
  const jobSection = workflow.split('\njobs:\n')[1];
  const definitions = [...jobSection.matchAll(/^  ([\w-]+):\n([\s\S]*?)(?=^  [\w-]+:\n|$(?![\s\S]))/gm)];
  assert(definitions.length > 5, 'Use the complete release job inventory');
  for (const resume of [false, true]) {
    const inventory = definitions.map(([, id, body]) => {
      const declared = body.match(/^    name: (.+)$/m)?.[1];
      const conditional = declared?.match(/^\$\{\{ inputs.resume_dev6_publication && '([^']+)' \|\| '([^']+)' \}\}$/);
      if (id === 'publish' || id === 'dev6-publication-resume') assert(conditional, 'Both publisher names must be conditional');
      return {id, name: conditional ? conditional[resume ? 1 : 2] : declared || id, status: 'completed', conclusion: 'success'};
    });
    const activeId = resume ? 'dev6-publication-resume' : 'publish';
    const active = inventory.find(j => j.id === activeId);
    const inactive = inventory.find(j => j.id === (resume ? 'publish' : 'dev6-publication-resume'));
    assert.equal(active.name, 'publish');
    assert.notEqual(inactive.name, 'publish');
    inactive.conclusion = 'skipped';
    assert.equal(inventory.filter(j => j.name === 'publish').length, 1);
    for (const status of ['queued', 'in_progress']) {
      active.status = status;
      assert.equal(scopedPublisherFinished(inventory), false, `${resume ? 'recovery' : 'ordinary'} publisher must keep waiting`);
    }
    active.status = 'completed';
    for (const conclusion of ['success', 'failure', 'skipped', 'cancelled']) {
      active.conclusion = conclusion;
      assert.equal(scopedPublisherFinished(inventory), true, 'Terminal selected publisher without a receipt must close the wait');
    }
  }
});

test('large multi-page release inventory survives the real subprocess boundary without truncation', () => {
  const pages = [Array.from({length: 50}, (_, i) => ({id: i + 1000, tag_name: `v0.0.${i}`,
    body: 'Synthetic release notes'.repeat(2200)})), [{...release, draft: true}]];
  const input = JSON.stringify(pages);
  assert(Buffer.byteLength(input) > 1024 * 1024);
  const args = ['-e', 'process.stdout.write(require("node:fs").readFileSync(0))'];
  assert.throws(() => execFileSync(process.execPath, args, {input, encoding: 'utf8'}), error => error.code === 'ENOBUFS');
  const result = publicationCommand(process.execPath, args, {input});
  assert.equal(result, input);
  const decoded = JSON.parse(result);
  assert.equal(selectRelease(decoded, version).id, release.id);
  assert.throws(() => selectRelease([...decoded, [{...release, draft: true}]], version), /exactly one release/);
});

test('publication command output remains bounded above the valid large-list case', () => {
  assert.throws(() => publicationCommand(process.execPath,
    ['-e', `process.stdout.write('x'.repeat(${PUBLICATION_MAX_BUFFER + 1}))`]), error => error.code === 'ENOBUFS');
});

test('exact scoped packages, draft and installed alias produce a complete barrier', () => {
  validateSource(source); validateScoped(scoped, m); assertSourceRun(sourceRun, source);
  assertDraft(release, scoped); validateAlias(alias, scoped, aliasRun, jobs);
  assert.equal(readyName(source), 'scoped-ready-100-2');
  assert.equal(aliasName(source, aliasRun), 'alias-ready-100-2-400-3');
});
test('selected source may differ from the dispatch workflow head SHA', () => {
  assert.notEqual(sourceRun.head_sha, source.sha);
  assert.doesNotThrow(() => assertSourceRun(sourceRun, source));
});
test('all source identity and current-attempt checks fail closed', () => {
  for (const mutation of [{repository: 'foreign/repo'}, {workflow: '.github/workflows/ci.yml'}, {run_id: '0'}, {run_attempt: 'x'}, {sha: 'main'}, {version: 'latest'}, {channel: 'latest'}, {release_id: 0}]) {
    assert.throws(() => validateSource({...source, ...mutation}));
  }
  for (const mutation of [{id: 101}, {run_attempt: 1}, {path: '.github/workflows/ci.yml'}, {event: 'pull_request'}, {status: 'completed'}, {status: 'queued'}, {head_repository: {full_name: 'foreign/repo'}}]) {
    assert.throws(() => assertSourceRun({...sourceRun, ...mutation}, source));
  }
});
test('missing, duplicate, mismatched or digestless scoped packages never open gate', () => {
  for (const mutate of [r => r.packages.pop(), r => r.packages.push(r.packages[0]), r => r.packages[0].version = '1.2.3', r => r.packages[0].integrity = '', r => r.packages[0].shasum = 'bad']) {
    const r = copy(scoped); mutate(r); assert.throws(() => validateScoped(r, m));
  }
});
test('all native binaries and complete asset identities must remain bound', () => {
  for (const mutate of [r => r.assets.pop(), r => r.assets[0].size = -1, r => r.assets[0].sha256 = '', r => r.binaries.pop(), r => r.binaries[0].sha256 = 'f'.repeat(64), r => r.binaries[0].target = 'wrong']) {
    const r = copy(scoped); mutate(r); assert.throws(() => validateScoped(r, m));
  }
  for (const mutate of [r => r.draft = false, r => r.id++, r => r.target_commitish = 'main', r => r.tag_name = 'v1.2.3', r => r.prerelease = false, r => r.assets.pop(), r => r.assets[0].digest = 'sha256:' + 'f'.repeat(64), r => r.assets[0].state = 'new']) {
    const r = copy(release); mutate(r); assert.throws(() => assertDraft(r, scoped));
  }
});
test('alias failure, no receipt, still-running job, stale run and stale attempt cannot publish parent', () => {
  assert.throws(() => validateAlias(null, scoped, aliasRun, jobs));
  assert.throws(() => validateAlias(alias, scoped, {...aliasRun, conclusion: 'failure'}, jobs));
  assert.throws(() => validateAlias(alias, scoped, {...aliasRun, status: 'in_progress'}, jobs));
  assert.throws(() => validateAlias(alias, scoped, aliasRun, [{name: 'publish-integrated', conclusion: null}]));
  assert.throws(() => validateAlias(alias, scoped, {...aliasRun, run_attempt: 4}, jobs));
  for (const mutate of [r => r.source.run_attempt = '1', r => r.source.run_id = '101', r => r.source.sha = 'f'.repeat(40), r => r.source.version = '1.2.3-dev.5', r => r.source.release_id++, r => r.publisher.run_id = '401', r => r.publisher.workflow = '.github/workflows/ci.yml', r => r.scoped_packages[0].integrity = '', r => r.alias.name = 'other', r => r.alias.version = '1.2.3', r => r.install.binary_sha256 = 'f'.repeat(64), r => r.install.version = '1.2.3']) {
    const r = copy(alias); mutate(r); assert.throws(() => validateAlias(r, scoped, aliasRun, jobs));
  }
});
test('safe failed-job rerun needs fresh receipts while immutable package identities remain unchanged', () => {
  const retried = copy(scoped); retried.source.run_attempt = '3';
  assert.notEqual(readyName(retried.source), readyName(scoped.source));
  assert.deepEqual(retried.packages, scoped.packages);
  assert.throws(() => validateAlias(alias, retried, aliasRun, jobs));
  const newAlias = copy(alias); newAlias.source.run_attempt = '3';
  validateAlias(newAlias, retried, aliasRun, jobs);
});

test('workflow contract keeps trust identities, unprivileged waiting and acyclic publication locks', () => {
  const root = new URL('../../', import.meta.url);
  const child = readFileSync(new URL('.github/workflows/npm-alias.yml', root), 'utf8').replace(/\r\n/g, '\n');
  const parent = readFileSync(new URL('.github/workflows/release.yml', root), 'utf8').replace(/\r\n/g, '\n');
  const helper = readFileSync(new URL('npm/scripts/release-publication.mjs', root), 'utf8').replace(/\r\n/g, '\n');
  assert.match(child, /types: \[in_progress\]/);
  assert.doesNotMatch(child.slice(0, child.indexOf('jobs:')), /concurrency:/);
  const waiting = child.split('  await-scoped:')[1].split('  publish-integrated:')[0];
  assert.doesNotMatch(waiting, /concurrency:|id-token:/);
  const publishing = child.split('  publish-integrated:')[1].split('\n  publish:')[0];
  assert.match(publishing, /needs: await-scoped/);
  assert.match(publishing, /ref: \$\{\{ needs.await-scoped.outputs.sha \}\}/);
  assert.match(publishing, /group: npm-rsrs-cli-publication\n      queue: max\n      cancel-in-progress: false/);
  assert.match(publishing, /contents: read\n      actions: read\n      id-token: write/);
  assert.doesNotMatch(publishing, /contents: write|actions: write|workflow_call/);
  assert.match(child.split('\n  publish:')[1], /if: github.event_name == 'workflow_dispatch'/);
  const final = parent.split('\n  publish:')[1];
  const indices = ['--publish --tag', 'scoped-ready', 'name: scoped-ready-', 'await-alias', 'release-publication.mjs finalize'].map(s => final.indexOf(s));
  assert(indices.every(i => i >= 0));
  assert.deepEqual(indices, [...indices].sort((a,b) => a-b));
  assert.equal((helper.match(/'--draft=false'/g) || []).length, 1);
  assert(final.indexOf('release-publication.mjs protocol') < final.indexOf('--publish --tag'));
  assert.match(parent, /- 'npm\/scripts\/pack\.mjs'/);
  assert.match(final, /group: cli-release-publication\n      queue: max\n      cancel-in-progress: false/);
  for (const name of ['Verify scoped registry propagation', 'Require the matching short-package', 'Make the complete release public']) {
    assert.match(final.slice(final.indexOf(`- name: ${name}`)).split('\n      - ')[0], /!\(inputs.repair_dev12 \|\| inputs.repair_dev14\)/);
  }
});
test('two overlapping Releases progress without waiting while holding the opposite alias lock', () => {
  // Model the actual lock graph asserted above. B's early ready wait has no lock.
  let publication = 'A', aliasLock = null;
  const ready = new Set(['A']), done = new Set();
  const acquireAlias = id => { if (!ready.has(id) || aliasLock) return false; aliasLock = id; return true; };
  assert.equal(acquireAlias('B'), false); // B waits for scoped-ready without locking.
  assert.equal(acquireAlias('A'), true);
  done.add('A'); aliasLock = null;
  assert(done.has(publication)); publication = 'B'; ready.add('B');
  assert.equal(acquireAlias('B'), true); done.add('B'); aliasLock = null;
  assert(done.has(publication));
});

test('existing lightweight or resolved annotated tag must identify the release source', () => {
  assertTagCommit(null, source);
  assertTagCommit({type: 'commit', sha: source.sha}, source);
  assert.throws(() => assertTagCommit({type: 'commit', sha: 'f'.repeat(40)}, source));
  assert.throws(() => assertTagCommit({type: 'tag', sha: source.sha}, source));
});

test('missing is pending, but duplicate, expired or foreign-run artifacts are rejected', () => {
  const a = {expired: false, workflow_run: {id: 100}};
  assert.equal(validateArtifact([], 100), null);
  assert.equal(validateArtifact([a], 100), a);
  assert.throws(() => validateArtifact([a, a], 100));
  assert.throws(() => validateArtifact([{...a, expired: true}], 100));
  assert.throws(() => validateArtifact([a], 101));
});

test('all Actions uploads, including both handshake receipts, retain evidence for one day', () => {
  const root = new URL('../../.github/workflows/', import.meta.url);
  let uploads = 0;
  for (const file of readdirSync(root).filter(name => /\.ya?ml$/.test(name))) {
    const workflow = readFileSync(new URL(file, root), 'utf8');
    for (const match of workflow.matchAll(/^([ \t]*)(- )?uses: actions\/upload-artifact@[^\s]+.*$/gm)) {
      const stepIndent = match[1].length - (match[2] ? 0 : 2);
      const tail = workflow.slice(match.index + match[0].length);
      const nextStep = tail.search(new RegExp(`\\n[ \t]{0,${stepIndent}}\\S`));
      const body = nextStep < 0 ? tail : tail.slice(0, nextStep);
      assert.match(body, /^[ \t]+retention-days: 1[ \t]*$/m, `${file}: every upload must retain exactly one day`);
      uploads++;
    }
  }
  assert.equal(uploads, 29, 'preserve existing uploads, both handshake receipts and both strict recovery evidence uploads');
});

test('draft release is resolved from every list page with exactly one matching tag', () => {
  const draft = {...release, draft: true};
  assert.equal(selectRelease([[{id: 299, tag_name: 'v1.2.3-dev.3'}], [draft]], version), draft);
  assert.throws(() => selectRelease([[{id: 299, tag_name: 'v1.2.3-dev.3'}]], version), /exactly one release/);
  assert.throws(() => selectRelease([[draft], [draft]], version), /exactly one release/);
  assert.throws(() => selectRelease([[{...draft, id: 0}]], version), /exactly one release/);
  assert.throws(() => selectRelease([null], version), /Invalid paginated/);
  assert.throws(() => selectRelease([[{...draft, draft: false}]], version), /must still be a draft/);
  const helper = readFileSync(new URL('./release-publication.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(helper, /releases\/tags\//);
  assert.match(helper, /selectRelease\(pages\(`/);
});
