import {installPinnedRuntime} from '../../scripts/ci-install-pinned-runtime.mjs';
import test from 'node:test';
import {gzipSync,gunzipSync} from 'node:zlib';
import {publishedAssetNames, validatePublishedRelease, validatePublishedMetadata, inspectPublishedRelease, inspectRuntimeProducer, downloadPublishedAsset, verifyPublishedTarget, consumePublishedTarget, extractPublishedArchive, verifyCorePayload, validatePublishedCompatibility, validatePublishedProcessEvidence, validatePublishedFull, validatePublishedPackage} from './extract-artifact.mjs';
import assert from 'node:assert/strict';
import {existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync} from 'node:fs';
import {createServer} from 'node:http';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {promisify} from 'node:util';
import {createHash} from 'node:crypto';
import {execFile, execFileSync} from 'node:child_process';
import {waitForPublicInstall, publicInstallArgs, publicInstallPlatform, PUBLICATION_MAX_BUFFER, publicationCommand, scopedPublisherFinished, selectRelease, validateArtifact, assertTagCommit, assertDraft, assertSourceRun, validateAlias, validateScoped, validateSource, readyName, aliasName} from './release-publication.mjs';

const m = JSON.parse(readFileSync(new URL('../artifact-manifest.json', import.meta.url))); m.npmScope = '@rsrsai/cli'; // Historical receipt layout.
delete m.artifactLayout;
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
  const frontend={...m,artifactLayout:'cli-frontend-v2'},receipt=copy(scoped);
  receipt.assets=receipt.assets.filter(a=>!a.name.endsWith('-runtime.tar.gz'));
  validateScoped(receipt,frontend);
  assert.throws(()=>validateScoped(scoped,frontend));
  assert.throws(()=>validateScoped(receipt,m));
  assert.throws(()=>validateScoped(receipt,{...frontend,artifactLayout:'unknown'}));
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
  assert.doesNotMatch(child, /workflow_run:/);
  assert.match(child, /release_attempt:/);
  assert.doesNotMatch(child.slice(0, child.indexOf('jobs:')), /concurrency:/);
  const waiting = child.split('  await-scoped:')[1].split('  publish-integrated:')[0];
  assert.doesNotMatch(waiting, /concurrency:|id-token:/);
  const publishing = child.split('  publish-integrated:')[1].split('\n  publish:')[0];
  assert.match(publishing, /needs: await-scoped/);
  assert.match(publishing, /ref: \$\{\{ needs.await-scoped.outputs.sha \}\}/);
  assert.match(publishing, /group: npm-rsrs-cli-publication\n      queue: max\n      cancel-in-progress: false/);
  assert.match(publishing, /contents: read\n      actions: read\n      id-token: write/);
  assert.doesNotMatch(publishing, /contents: write|actions: write|workflow_call/);
  assert.match(waiting, /Read this Release attempt scoped publication receipt once/);
  assert.doesNotMatch(waiting, /concurrency:|id-token:/);
  assert.match(child.split('\n  publish:')[1], /if: github.event_name == 'workflow_dispatch'/);
  const final = parent.split('\n  publish:')[1];
  const indices = ['--publish --accepted-only --verified-packs npm/publication-packages --tag', 'scoped-accepted', 'name: scoped-accepted-', 'gh workflow run npm-alias.yml', 'await-alias-accepted', 'release-publication.mjs finalize-accepted'].map(s => final.indexOf(s));
  assert(indices.every(i => i >= 0));
  assert.deepEqual(indices, [...indices].sort((a,b) => a-b));
  assert.equal((helper.match(/'--draft=false'/g) || []).length, 1);
  assert(final.indexOf('release-publication.mjs protocol') < final.indexOf('--publish --accepted-only --verified-packs npm/publication-packages --tag'));
  assert.match(parent, /tags: \['v\*'\]/);
  assert.match(final, /group: cli-release-publication\n      queue: max\n      cancel-in-progress: false/);
  assert.match(final, /contents: write\n      actions: write\n      id-token: write/);
  const resolver=helper.split('async function awaitScoped()')[1].split('// Retry only')[0];
  assert.doesNotMatch(resolver,/while\s*\(|sleep\(|deadline/);
  assert.match(resolver,/Exact scoped receipt missing/);
  for (const name of ['Bind successful scoped npm submissions', 'Require every matching npm submission', 'Make the complete release public']) {
    assert.match(final.slice(final.indexOf(`- name: ${name}`)).split('\n      - ')[0], /!\(inputs.repair_dev12 \|\| inputs.repair_dev14\)/);
  }
});

test('same-run scoped tarball reuse is explicit current-main only; historical, prepared and repair paths keep packing',()=>{
  const workflow=readFileSync(new URL('../../.github/workflows/release.yml',import.meta.url),'utf8').replace(/\r\n/g,'\n');
  const publisher=workflow.split('\n  publish:')[1];
  const expression=publisher.match(/^      REUSE_VALIDATED_PACKS: \$\{\{ (.+) \}\}$/m)?.[1];
  assert(expression,'reuse must be selected from the workflow trust context');
  const repository=expression.match(/github.repository == '([^']+)'/)?.[1];assert(repository);
  const selected=new Function('github','needs','inputs',`return (${expression});`);
  for(const owner of [repository,'fork/repo']) for(const event of ['workflow_dispatch','push']) for(const ref of ['refs/heads/main','refs/heads/feature'])
    for(const exact of [true,false]) for(const prepared of ['', '100']) for(const repair12 of [false,true])
    for(const repair14 of [false,true]) for(const reuse of [false,true]) {
      const github={repository:owner,event_name:event,ref,sha:'a'.repeat(40)},needs={plan:{outputs:{sha:(exact?'a':'b').repeat(40)}}};
      const inputs={prepared_run:prepared,repair_dev12:repair12,repair_dev14:repair14,reuse_dev12_validation:reuse};
      assert.equal(selected(github,needs,inputs),owner===repository&&event==='workflow_dispatch'&&ref==='refs/heads/main'&&exact&&!prepared&&!repair12&&!repair14&&!reuse);
    }
  const verify=publisher.split('- name: Verify release artifacts and prepare every scoped npm package')[1].split('\n      - ')[0];
  assert.match(verify,/CLI_SHA: \$\{\{ needs.plan.outputs.sha \}\}/);
  assert.match(verify,/if \[ "\$REUSE_VALIDATED_PACKS" = true \]; then\n\s+node npm\/scripts\/verify-packages.mjs release-assets --reuse-packs "\$RUNNER_TEMP\/validated-npm" --download --export-packs npm\/publication-packages\n\s+else\n\s+node npm\/scripts\/verify-packages.mjs release-assets --pack npm\/publication-packages\n\s+fi/);
  const publish=publisher.split('- name: Publish npm using Trusted Publishing')[1].split('\n      - ')[0];
  assert.doesNotMatch(publish,/npm\/scripts\/pack.mjs.*\$RUNNER_TEMP\/validated-npm/);
  assert.match(publish,/--publish --accepted-only --verified-packs npm\/publication-packages --tag/);
  assert.match(publisher,/name: npm-publication-packages/);
  assert.match(publisher,/if: inputs.prepared_run != ''\n\s+run: node npm\/scripts\/verify-packages.mjs release-assets --pack npm\/release-packages/);
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
  assert.throws(() => assertTagCommit(null, source, {allowMissing: false}));
  assertTagCommit({type: 'commit', sha: source.sha}, source, {allowMissing: false});
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
  // The latest-release upgrade no longer uploads a historical draft cache.
  assert.equal(uploads, 60, 'preserve current publication/source evidence, both Client2 results and the published online receipt');
  const compatibility = readFileSync(new URL('client2-launcher-regression.yml', root), 'utf8');
  assert.match(compatibility, /name: client2-launcher-raw-\$\{\{ matrix.target \}\}-\$\{\{ github.run_id \}\}-\$\{\{ github.run_attempt \}\}/);
  const launcherRaw = [
    '          name: client2-launcher-raw-${{ matrix.target }}-${{ github.run_id }}-${{ github.run_attempt }}',
    '          path: |',
    '            ${{ runner.temp }}/client2-launcher-regression.json',
    '            ${{ runner.temp }}/client2-gui-probe/report.json',
    '            ${{ runner.temp }}/client2-gui-probe/native-gui.json',
    '            ${{ runner.temp }}/client2-gui-probe/workspace.png',
    '          if-no-files-found: warn',
    '          retention-days: 1',
  ].join('\n');
  assert(compatibility.replace(/\r\n/g, '\n').includes(launcherRaw),
    'original Client2 raw and exact GUI evidence paths must belong to the same named one-day upload');
  const candidate = readFileSync(new URL('migration-keyring-check.yml', root), 'utf8');
  assert.doesNotMatch(candidate, /runtime_candidate_sha:|source-account-regression:|\.account-runtime/);
  assert.match(candidate, /release_run_id:/);
  assert.match(candidate, /targeted-native-migration\/migration-platform-gate\.json/);
  assert.match(candidate, /native-migration-keyring\/keyring-selftest\.json/);
  const release = readFileSync(new URL('release.yml', root), 'utf8');
  const manifest = JSON.parse(readFileSync(new URL('../../npm/artifact-manifest.json', root), 'utf8'));
  const imported = [...release.matchAll(/name: cli-release-([\w-]+)/g)].map(match => match[1]);
  assert.deepEqual(imported.sort(), manifest.targets.map(target => target.triple).sort());
  const ci = readFileSync(new URL('ci.yml', root), 'utf8');
  const client2SourceRaw = [
    '          name: client2-source-raw-${{ github.run_id }}-${{ github.run_attempt }}',
    '          path: ${{ runner.temp }}/client2-coverage.json',
    '          if-no-files-found: error',
    '          retention-days: 1',
  ].join('\n');
  assert(ci.replace(/\r\n/g, '\n').includes(client2SourceRaw),
    'instrumented Client2 name, report path and one-day retention must belong to the same upload');
  assert.match(ci, /name: required-tests-raw-cli-core-/);
  assert.match(ci, /name: required-tests-report-/);
  assert.match(ci, /name: private-business-credentials-/);
  const crates = readFileSync(new URL('publish-crates.yml', root), 'utf8');
  assert.match(crates, /name: protocol-package-verification/);
  assert.doesNotMatch(crates, /name: sdk-package-verification/);
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


test('alias job and parent receipt budgets cover both propagation waits and clean install', () => {
  const root = new URL('../../', import.meta.url);
  const helper = readFileSync(new URL('npm/scripts/release-publication.mjs', root), 'utf8').replace(/\r\n/g, '\n');
  const child = readFileSync(new URL('.github/workflows/npm-alias.yml', root), 'utf8').replace(/\r\n/g, '\n');
  const parent = readFileSync(new URL('.github/workflows/release.yml', root), 'utf8').replace(/\r\n/g, '\n');
  const minutes = (text, pattern) => {
    const match = text.match(pattern);
    assert(match, 'The publication timeout must remain explicitly bound to its call or job');
    return Number(match[1]);
  };
  const scoped = minutes(helper, /verifyPackages\(scoped\.packages, \{[^}]*timeoutMs: (\d+) \* 60 \* 1000/);
  const alias = minutes(helper, /source\.channel, \{requireInstallIndex: true, timeoutMs: (\d+) \* 60 \* 1000/);
  const install = minutes(helper, /options\.timeoutMs \?\? (\d+) \* 60 \* 1000;\n  const deadline = now\(\)/);
  const job = minutes(child.split('  publish-integrated:')[1].split('\n  publish:')[0], /timeout-minutes: (\d+)/);
  const receipt = minutes(helper, /async function awaitAlias\(\) \{[\s\S]*?Date\.now\(\) \+ (\d+) \* 60 \* 1000;/);
  assert.equal(alias, scoped);
  assert(scoped >= 30);
  assert(job > scoped + alias + install, 'Job must leave room for setup and packaging');
  assert(receipt > job, 'Receipt observer must outlive the publisher');
  const legacyParent = parent.slice(parent.indexOf('  dev6-publication-resume:'));
  const observers = [...legacyParent.matchAll(/timeout-minutes: (\d+)\n        env:\n          GH_TOKEN: \$\{\{ github\.token \}\}\n        run: node npm\/scripts\/release-publication\.mjs await-alias/g)];
  assert.equal(observers.length, 1);
  assert(observers.every(match => Number(match[1]) > receipt));
  const recovery = minutes(parent.split('\n  dev6-publication-resume:')[1], /timeout-minutes: (\d+)/);
  const revalidation = minutes(helper, /options\.timeoutMs \?\? (\d+) \* 60 \* 1000/);
  assert(recovery > revalidation + receipt, 'Historical recovery needs revalidation and observation time');
});

test('npm resolver visibility delay retries exact pinned packages inside one deadline', async () => {
  let elapsed = 0, attempts = 0;
  const remaining = [], logged = [];
  const specs = [...scoped.packages, alias.alias].map(p => `${p.name}@${p.version}`);
  const output = await waitForPublicInstall(timeout => {
    remaining.push(timeout);
    elapsed += 2;
    if (++attempts <= 2) throw Object.assign(new Error('npm failed'), {status: 1,
      stdout: JSON.stringify({error: {code: 'ETARGET', summary: `No matching version found for ${specs[attempts - 1]}.`}})});
    return 'installed';
  }, specs, {timeoutMs: 30, pollMs: 5, now: () => elapsed, sleep: async ms => {elapsed += ms;},
    onRetry: (_, attempt) => logged.push(attempt)});
  assert.equal(output, 'installed');
  assert.deepEqual(remaining, [30, 23, 16]);
  assert.deepEqual(logged, [1, 2]);
});

test('npm resolver failures remain bounded and preserve the original error', async () => {
  const error = Object.assign(new Error('npm failed'), {status: 1,
    stdout: JSON.stringify({error: {code: 'ETARGET', summary: `No matching version found for rsrs-cli@${version}.`}})});
  for (const timeoutMs of [11, 30]) {
    let elapsed = 0, attempts = 0;
    await assert.rejects(waitForPublicInstall(() => {attempts++; throw error;}, [`rsrs-cli@${version}`],
      {timeoutMs, pollMs: 5, now: () => elapsed, sleep: async ms => {elapsed += ms;}}), actual => actual === error);
    assert.equal(attempts, 3);
  }
  let attempts = 0;
  await assert.rejects(waitForPublicInstall(() => {attempts++; throw error;}, [`rsrs-cli@${version}`],
    {timeoutMs: 5, pollMs: 5}), actual => actual === error);
  assert.equal(attempts, 1);
});

test('foreign ETARGET, malformed JSON, integrity, authorization and process failures never retry', async () => {
  const report = summary => JSON.stringify({error: {code: 'ETARGET', summary}});
  for (const fields of [
    {stdout: report('No matching version found for foreign@1.0.0.')},
    {stdout: report(`No matching version found for rsrs-cli@1.2.3-dev.99.`)},
    {stdout: 'invalid JSON'},
    {stdout: JSON.stringify({error: {code: 'EINTEGRITY', summary: 'bad digest'}})},
    {stdout: JSON.stringify({error: {code: 'E401', summary: 'unauthorized'}})},
    {status: null, signal: 'SIGTERM', code: 'ETIMEDOUT', stdout: report(`No matching version found for rsrs-cli@${version}.`)},
  ]) {
    const error = Object.assign(new Error('npm failed'), {status: 1}, fields);
    let attempts = 0;
    await assert.rejects(waitForPublicInstall(() => {attempts++; throw error;}, [`rsrs-cli@${version}`]),
      actual => actual === error);
    assert.equal(attempts, 1);
  }
});

test('real publication install opts into npm freshness and structured errors without changing its pin', () => {
  const args = publicInstallArgs('/isolated/install', '/isolated/cache', version);
  assert(args.includes('--prefer-online'));
  assert(args.includes('--json'));
  assert.equal(args.at(-1), `rsrs-cli@${version}`);
  assert.equal(args[args.indexOf('--registry') + 1], 'https://registry.npmjs.org');
});

test('actual npm resolver recovers from an offline registry index delay with a fresh request', async t => {
  const root = mkdtempSync(path.join(tmpdir(), 'rsrs-install-index-test-'));
  t.after(() => rmSync(root, {recursive: true, force: true}));
  const npmCli = [
    path.join(path.dirname(process.execPath), 'node_modules/npm/bin/npm-cli.js'),
    path.resolve(path.dirname(process.execPath), '../lib/node_modules/npm/bin/npm-cli.js'),
  ].find(existsSync);
  assert(npmCli, 'The test requires the npm installed beside Node');
  const env = {...process.env};
  for (const key of Object.keys(env)) if (/^(?:npm_config_|NODE_AUTH_TOKEN$|NPM_TOKEN$|GH_TOKEN$|GITHUB_TOKEN$|ACTIONS_ID_TOKEN_REQUEST_)/i.test(key)) delete env[key];
  Object.assign(env, {HOME: root, USERPROFILE: root, NPM_CONFIG_CACHE: path.join(root, 'cache'),
    NPM_CONFIG_USERCONFIG: path.join(root, 'empty.npmrc'), NPM_CONFIG_GLOBALCONFIG: path.join(root, 'global.npmrc')});
  writeFileSync(env.NPM_CONFIG_USERCONFIG, ''); writeFileSync(env.NPM_CONFIG_GLOBALCONFIG, '');
  const pkg = path.join(root, 'package');
  mkdirSync(pkg);
  writeFileSync(path.join(pkg, 'package.json'), JSON.stringify({name: 'rsrs-cli', version}));
  const execute = promisify(execFile);
  await execute(process.execPath, [npmCli, 'pack', '--ignore-scripts', '--json', '--pack-destination', root], {cwd: pkg, env, timeout: 30000});
  const tarball = readFileSync(path.join(root, readdirSync(root).find(file => file.endsWith('.tgz'))));
  let visible = false, indexRequests = 0, retries = 0, attempts = 0;
  const server = createServer((request, response) => {
    response.setHeader('Content-Type', 'application/json');
    if (request.url === '/rsrs-cli') {
      indexRequests++;
      const metadata = {name: 'rsrs-cli', version, dist: {
        tarball: `http://127.0.0.1:${server.address().port}/fixture.tgz`,
        integrity: `sha512-${createHash('sha512').update(tarball).digest('base64')}`,
        shasum: createHash('sha1').update(tarball).digest('hex')}};
      response.end(JSON.stringify({name: 'rsrs-cli', 'dist-tags': {dev: version},
        versions: visible ? {[version]: metadata} : {}}));
    } else if (request.url === '/fixture.tgz') {
      response.setHeader('Content-Type', 'application/octet-stream'); response.end(tarball);
    } else { response.statusCode = 404; response.end('{}'); }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => {server.close(resolve); server.closeAllConnections();}));
  const args = publicInstallArgs(path.join(root, 'install'), env.NPM_CONFIG_CACHE, version);
  args[args.indexOf('--registry') + 1] = `http://127.0.0.1:${server.address().port}`;
  args.splice(1, 0, '--ignore-scripts');
  await waitForPublicInstall(async timeout => {
    attempts++;
    try { return (await execute(process.execPath, [npmCli, ...args], {env, timeout})).stdout; }
    catch (error) {
      // execFileSync (production) calls this exit code status; execFile calls it code.
      error.status = error.code; throw error;
    }
  }, [`rsrs-cli@${version}`], {timeoutMs: 30000, pollMs: 1, onRetry: error => {
    assert.equal(JSON.parse(error.stdout).error.code, 'ETARGET');
    retries++; visible = true;
  }});
  assert.equal(retries, 1);
  assert.equal(attempts, 2);
  assert(indexRequests >= 2, 'The retry must fetch the registry again rather than reuse stale cache');
  assert.equal(JSON.parse(readFileSync(path.join(root, 'install/node_modules/rsrs-cli/package.json'))).version, version);
});


test('public installation selects explicit libc and requires actual matching host architecture',()=>{
  assert.equal(publicInstallPlatform('linux-x64-gnu',{platform:'linux',arch:'x64'}).libc,'glibc');
  for(const [platform,libc] of [['linux-arm64','musl'],['linux-arm64-gnu','glibc']]){
    assert.deepEqual(publicInstallPlatform(platform,{platform:'linux',arch:'arm64'}),{arch:'arm64',libc,pkg:'@rsrsai/'+platform,platform});
    assert.throws(()=>publicInstallPlatform(platform,{platform:'linux',arch:'x64'}));
    assert.throws(()=>publicInstallPlatform(platform,{platform:'darwin',arch:'arm64'}));
  }
  assert.throws(()=>publicInstallPlatform('foreign',{platform:'linux',arch:'arm64'}));
});

test('public release assets bind exact ID, dereferenced tag SHA, size and digest; paginated APIs never accept a draft', async () => {
  const bytes = Buffer.from('synthetic asset only'), digest = createHash('sha256').update(bytes).digest('hex');
  const asset = {id: 8, name: 'fixed.bin', size: bytes.length, sha256: digest};
  const part = {repository: 'risense-ai/respire-cli', release_id: 7, version: '1.0.21-dev.5', source_sha: 'a'.repeat(40), producer:{run_id:91,run_attempt:2}, assets: [asset]};
  const release = {id: 7, tag_name: 'v1.0.21-dev.5', draft: false, published_at: '2026-11-05T00:00:00Z'};
  const actual = {...asset, state: 'uploaded', digest: `sha256:${digest}`};
  validatePublishedRelease(part, release, [actual], part.source_sha);
  for (const bad of [{draft: true}, {id: 9}, {tag_name: 'v1.0.21-dev.6'}, {published_at: null}]) {
    assert.throws(() => validatePublishedRelease(part, {...release, ...bad}, [actual], part.source_sha));
  }
  for (const bad of [{id: 9}, {name: 'other.bin'}, {size: 1}, {state: 'new'}, {digest: 'sha256:' + 'b'.repeat(64)}]) {
    assert.throws(() => validatePublishedRelease(part, release, [{...actual, ...bad}], part.source_sha));
  }
  assert.throws(() => validatePublishedRelease(part, release, [actual], 'b'.repeat(40)));
  assert.throws(() => validatePublishedRelease(part, release, [actual, actual], part.source_sha));
  const calls = [], tag = 'b'.repeat(40);
  const fetcher = async url => {
    calls.push(url);
    let value;
    if (url.endsWith('/releases/7')) value = release;
    else if (url.endsWith('/git/ref/tags/v1.0.21-dev.5')) value = {object: {type: 'tag', sha: tag}};
    else if (url.endsWith('/git/tags/' + tag)) value = {object: {type: 'commit', sha: part.source_sha}};
    else if (url.endsWith('page=1')) value = [actual, ...Array.from({length: 99}, (_, i) => ({id: 100 + i, name: `extra-${i}`}))];
    else if (url.endsWith('page=2')) value = [];
    else if (url.includes('/actions/runs/91/attempts/2')) value = {id:91,run_attempt:2,head_sha:part.source_sha,status:'completed',conclusion:'success',path:'.github/workflows/release.yml',repository:{full_name:part.repository}};
    else throw Error('Unexpected metadata request ' + url);
    return {status: 200, json: async () => value};
  };
  assert.equal((await inspectPublishedRelease(part, {fetcher})).source_sha, part.source_sha);
  assert.ok(calls.some(url => url.endsWith('page=2')));
  for (const changed of [{run_attempt:3},{head_sha:'f'.repeat(40)},{conclusion:'failure'},
    {status:'in_progress'},{path:'.github/workflows/other.yml'},{repository:{full_name:'foreign/cli'}}]) {
    await assert.rejects(inspectPublishedRelease(part,{fetcher:async url=>{
      const response=await fetcher(url);
      return url.includes('/actions/runs/')?{status:200,json:async()=>({...await response.json(),...changed})}:response;
    }}),/producer run\/source\/attempt/);
  }
  await assert.rejects(inspectPublishedRelease(part, {fetcher: async () => ({status: 404})}), /HTTP 404/);
  await assert.rejects(inspectPublishedRelease(part, {fetcher: async url => {
    if (url.includes('/git/')) return {status: 200, json: async () => ({object: {type: 'tag', sha: tag}})};
    return fetcher(url);
  }}), /exact commit/);
  const root = mkdtempSync(path.join(tmpdir(), 'published-assets-test-'));
  try {
    const fetchBytes = async () => new Response(bytes);
    await downloadPublishedAsset(part, asset, root, {fetcher: fetchBytes});
    assert.deepEqual(readFileSync(path.join(root, asset.name)), bytes);
    await assert.rejects(downloadPublishedAsset(part, asset, root, {fetcher: fetchBytes}), /EEXIST/);
    assert.deepEqual(readFileSync(path.join(root, asset.name)), bytes, 'never remove an existing asset');
    const bad = {...asset, name: 'bad.bin', sha256: 'f'.repeat(64)};
    await assert.rejects(downloadPublishedAsset(part, bad, root, {fetcher: fetchBytes}), /hash\/size/);
    assert.equal(existsSync(path.join(root, bad.name)), false);
    await assert.rejects(downloadPublishedAsset(part, {...asset, name: 'oversize.bin', size: 1}, root, {fetcher: fetchBytes}), /approved size/);
    assert.equal(existsSync(path.join(root, 'oversize.bin')), false);
  } finally { rmSync(root, {recursive: true, force: true}); }
});
test('published CLI and Runtime metadata cannot swap source, version, target, hashes or unsafe payload inventory', () => {
  const target = 'x86_64-unknown-linux-gnu', hash = 'a'.repeat(64);
  const spec = {cli: {version, source_sha: sha, producer:{run_id:91,run_attempt:2}, assets: [
    {name: `rsrs-${target}`, size:64, sha256: hash}]},
    runtime: {version, source_sha: sha, assets: [{name: `rsrs-runtime-${target}`, sha256: hash},
      {name: `rsrs-runtime-${target}.tar.gz`, sha256: hash}]}};
  const cli = {schema_version: 2, artifact_layout:'cli-frontend-v2', git_sha: sha, version, target, binary_file: `rsrs-${target}`,
    binary_size:64, binary_sha256: hash, producer:spec.cli.producer};
  const runtime = {schema_version: 2, source_commit: sha, runtime_version: version, target_triple: target,
    binary_file: `rsrs-runtime-${target}`, archive_file: `rsrs-runtime-${target}.tar.gz`, binary_sha256: hash,
    archive_sha256: hash, protocol_range: {minimum: 1, maximum: 1}, capabilities: {business_executor: '1', mcp_server: '1'},
    files: [{path: 'rsrs-runtime', size: 10, sha256: hash}]};
  validatePublishedMetadata(spec, target, cli, runtime);
  for (const invalid of [{git_sha: 'c'.repeat(40)}, {version: '1.0.21-dev.99'}, {target: 'other'},
    {binary_sha256: 'f'.repeat(64)}, {runtime_file: 'other.tar.gz'}, {binary_size:65}, {producer:{run_id:92,run_attempt:2}}, {producer:{run_id:91,run_attempt:3}}]) {
    assert.throws(() => validatePublishedMetadata(spec, target, {...cli, ...invalid}, runtime));
  }
  for (const invalid of [{source_commit: 'c'.repeat(40)}, {runtime_version: '1.0.21-dev.99'},
    {target_triple: 'other'}, {archive_sha256: 'f'.repeat(64)}, {binary_sha256: 'f'.repeat(64)},
    {protocol_range: {minimum: 1, maximum: 2}}, {capabilities: {}}, {files: []},
    {files: [{path: '../escape', size: 1, sha256: hash}]}, {files: [runtime.files[0], runtime.files[0]]}]) {
    assert.throws(() => validatePublishedMetadata(spec, target, cli, {...runtime, ...invalid}));
  }
});

function producerZip(entries) {
  return execFileSync(process.platform === 'win32' ? 'py' : 'python3',
    [...(process.platform === 'win32' ? ['-3'] : []), '-I', '-c', `import base64,io,json,sys,zipfile
b=io.BytesIO()
with zipfile.ZipFile(b,'w',compression=zipfile.ZIP_DEFLATED) as z:
 for name,data,mode in json.load(sys.stdin):
  e=zipfile.ZipInfo(name); e.external_attr=mode<<16; z.writestr(e,base64.b64decode(data))
sys.stdout.buffer.write(b.getvalue())`],
    {input:JSON.stringify(entries.map(([name, bytes, mode=0o100644]) => [name, Buffer.from(bytes).toString('base64'), mode])), timeout:10000});
}
function runtimeProducerFixture(part, target, metadata, archive) {
  const digest = bytes => createHash('sha256').update(bytes).digest('hex');
  const names = publishedAssetNames('runtime', target), producer = part.producer;
  const report = {target, version:part.version, source_commit:part.source_sha, run_id:String(producer.run_id),
    run_attempt:String(producer.run_attempt), archive_sha256:digest(archive),
    binary_sha256:part.assets.find(a => a.name === names[1]).sha256, passed:true, g1Passed:false};
  const jobs = [`Release (${target})`,`Native regression (${target})`].map((name, i) => ({id:i+11, name,
    run_id:producer.run_id, run_attempt:producer.run_attempt, head_sha:part.source_sha, status:'completed', conclusion:'success',
    started_at:'2026-11-05T00:00:00Z', completed_at:'2026-11-05T00:01:00Z'}));
  const zips = new Map(), artifacts = [];
  for (const [i, name, entries] of [[0,`runtime-release-${target}`,[[names[0],metadata],[names[2],archive]]],
    [1,`runtime-smoke-${target}`,[[`runtime-smoke-${target}.json`,JSON.stringify(report)]]]]) {
    const bytes = producerZip(entries); zips.set(i+31, bytes);
    artifacts.push({id:i+31, name, size_in_bytes:bytes.length, digest:`sha256:${digest(bytes)}`, expired:false,
      workflow_run:{id:producer.run_id, head_sha:part.source_sha}, created_at:'2026-11-05T00:00:20Z', updated_at:'2026-11-05T00:00:21Z'});
  }
  return {jobs, artifacts, zips, report,
    fetcher:async url => ({status:200, json:async () => {
      if (url.includes(`/attempts/${producer.run_attempt}/jobs?`)) return {jobs};
      assert(url.includes(`/runs/${producer.run_id}/artifacts?`)); return {artifacts};
    }}),
    artifactTransport:args => zips.get(Number(args.at(-1).split('/').at(-2))),
    replaceZip(index, entries) {
      const bytes=producerZip(entries), artifact=artifacts[index]; zips.set(artifact.id,bytes);
      artifact.size_in_bytes=bytes.length; artifact.digest=`sha256:${digest(bytes)}`;
    }};
}

test('published Runtime producer binds exact attempt reports and build bytes, including metadata', async () => {
  const target='x86_64-pc-windows-msvc', names=publishedAssetNames('runtime',target);
  const payloads=[Buffer.from('{"synthetic":"metadata"}'),Buffer.from('binary'),Buffer.from('archive')];
  const part={repository:'risense-ai/respire-runtime',version,source_sha:sha,producer:{run_id:91,run_attempt:2},
    assets:payloads.map((bytes,i)=>({name:names[i],size:bytes.length,sha256:createHash('sha256').update(bytes).digest('hex')}))};
  const fixture=()=>runtimeProducerFixture(part,target,payloads[0],payloads[2]);
  const run=f=>inspectRuntimeProducer(part,target,f);
  const evidence=await run(fixture());
  assert.equal(evidence.metadata_sha256,part.assets[0].sha256);assert.equal(evidence.binary_sha256,part.assets[1].sha256);
  assert.equal(evidence.archive_sha256,part.assets[2].sha256);assert.equal(evidence.run_attempt,2);assert.equal(evidence.artifacts.length,2);
  for(const change of [f=>f.jobs.pop(),f=>f.jobs.push(f.jobs[0]),f=>f.jobs[0].run_attempt=1,
    f=>f.jobs[0].run_id++,f=>f.jobs[0].head_sha='f'.repeat(40),f=>f.jobs[1].name='Native regression (other)',
    f=>f.jobs[0].status='in_progress',f=>f.jobs[1].conclusion='failure',f=>f.artifacts.pop(),f=>f.artifacts.push(f.artifacts[0]),
    f=>f.artifacts[0].expired=true,f=>delete f.artifacts[0].digest,f=>f.artifacts[0].workflow_run.id++,
    f=>f.artifacts[0].workflow_run.head_sha='f'.repeat(40),f=>f.artifacts[0].created_at='2026-11-04T00:00:00Z',
    f=>f.artifacts[0].updated_at='2026-11-06T00:00:00Z',f=>f.jobs[0].started_at='invalid',
    f=>f.artifacts[0].digest='sha256:'+'f'.repeat(64),f=>f.artifacts[0].size_in_bytes++,
    f=>f.zips.set(31,Buffer.from('tampered ZIP'))]) {
    const f=fixture();change(f);await assert.rejects(run(f));
  }
  for(const change of [r=>r.run_id='92',r=>r.run_attempt='1',r=>r.source_commit='f'.repeat(40),r=>r.target='other',
    r=>r.version='1.0.21-dev.99',r=>r.passed=false,r=>r.archive_sha256='f'.repeat(64),r=>r.binary_sha256='f'.repeat(64)]) {
    const f=fixture();change(f.report);f.replaceZip(1,[[`runtime-smoke-${target}.json`,JSON.stringify(f.report)]]);
    await assert.rejects(run(f),/native report\/source\/attempt\/bytes/);
  }
  for(const entries of [[[names[0],Buffer.from('{"synthetic":"different metadata"}')],[names[2],payloads[2]]],
    [[names[0],payloads[0]],[names[2],Buffer.from('different archive')]],
    [[names[0],payloads[0]]],[[names[0],payloads[0]],[names[0],payloads[0]],[names[2],payloads[2]]],
    [[names[0],payloads[0],0o120777],[names[2],payloads[2]]]]) {
    const f=fixture();f.replaceZip(0,entries);await assert.rejects(run(f));
  }
});

test('published target downloads and verifies both real file sets but records no process/full success before execution', async () => {
  const target = 'x86_64-unknown-linux-gnu', root = mkdtempSync(path.join(tmpdir(), 'published-target-test-'));
  const hash = bytes => createHash('sha256').update(bytes).digest('hex');
  const image = Buffer.alloc(64); image.set([0x7f, 0x45, 0x4c, 0x46, 2, 1]); image.writeUInt16LE(62, 18);
  const license = Buffer.from('synthetic license'), sdk = {sdk_version:'1.0.2-dev.23',manifest_sha256:'a'.repeat(64),archive_sha256:'b'.repeat(64),redistribution:'approved'};
  const core = Buffer.from(JSON.stringify({schema_version:1,target,sdk_version:sdk.sdk_version,redistribution:'permitted-under-included-license',files:[{path:'core-notices/CORE-SDK-LICENSE.txt',sha256:hash(license)}]}));
  const archive = syntheticTar([['core-runtime.json',core],['core-notices/CORE-SDK-LICENSE.txt',license],[`rsrs-runtime-${target}`,image]]);
  const fileHash = hash(image), archiveHash = hash(archive), manifestHash = 'd'.repeat(64);
  const cli = {schema_version: 2, artifact_layout:'cli-frontend-v2', git_sha: sha, version, target, binary_file: `rsrs-${target}`,
    binary_size:image.length, binary_sha256: fileHash, producer:{run_id:91,run_attempt:2}};
  const runtime = {schema_version: 2, source_commit: sha, runtime_version: version, target_triple: target,
    binary_file: `rsrs-runtime-${target}`, archive_file: `rsrs-runtime-${target}.tar.gz`, binary_sha256: fileHash,
    archive_sha256: archiveHash, protocol_range: {minimum: 1, maximum: 1}, capabilities: {business_executor: '1', mcp_server: '1'},
    compat:{min_cli:version,max_cli:'*'},
    files: [{path:'core-runtime.json',size:core.length,sha256:hash(core)},{path:'core-notices/CORE-SDK-LICENSE.txt',size:license.length,sha256:hash(license)}, {path: `rsrs-runtime-${target}`, size: image.length, sha256: fileHash}]};
  const bytes = new Map();
  const part = (kind, metadata, names, id) => ({repository: `risense-ai/respire-${kind}`, release_id: id, version, source_sha: sha, producer:{run_id:91,run_attempt:2},
    assets: [Buffer.from(JSON.stringify(metadata)), image, ...(kind === 'cli' ? [] : [archive])].map((value, n) => {
      const asset = {id: id * 10 + n, name: names[n], size: value.length, sha256: hash(value)};
      bytes.set(asset.id, value); return asset;
    })});
  const spec = {cli: part('cli', cli, [`cli-build-${target}.json`, cli.binary_file], 10),
    runtime: part('runtime', runtime, [`runtime-build-${target}.json`, runtime.binary_file, runtime.archive_file], 20)};
  const producer=runtimeProducerFixture(spec.runtime,target,bytes.get(spec.runtime.assets[0].id),archive);
  let corrupt = false;
  const fetcher = async url => {
    const kind = url.includes('/respire-runtime/') ? 'runtime' : 'cli', selected = spec[kind];
    if (url.includes('/jobs?') || url.includes('/artifacts?')) return producer.fetcher(url);
    if(url.includes('/contents/')) {
      const value=url.includes('runtime-pin.json')?{required:version,accept:`>=${version},<2.0.0`}:url.includes('artifact-manifest.json')?{artifactLayout:'cli-frontend-v2',cliVersion:version,targets:[{triple:target}]}:{targets:{[target]:sdk}};
      const body=Buffer.from(JSON.stringify(value));
      return {status:200,json:async()=>({type:'file',encoding:'base64',size:body.length,content:body.toString('base64'),sha:createHash('sha1').update(Buffer.concat([Buffer.from(`blob ${body.length}\0`),body])).digest('hex')})};
    }
    if (url.includes('/actions/runs/')) return {status:200,json:async()=>({id:91,run_attempt:2,head_sha:sha,status:'completed',conclusion:'success',path:'.github/workflows/release.yml',repository:{full_name:selected.repository}})};
    if (url.includes('/releases/assets/')) return new Response(corrupt ? 'bad' : bytes.get(Number(url.split('/').pop())));
    if (url.includes('/git/ref/')) return {status: 200, json: async () => ({object: {type: 'commit', sha}})};
    if (url.includes('/assets?')) return {status: 200, json: async () => selected.assets.map(a => ({...a, state: 'uploaded', digest: `sha256:${a.sha256}`}))};
    return {status: 200, json: async () => ({id: selected.release_id, tag_name: `v${version}`, draft: false, published_at: '2026-11-05T00:00:00Z'})};
  };
  const options={fetcher,artifactTransport:producer.artifactTransport};
  try {
    const destination = path.join(root, 'success');
    const receipt = await verifyPublishedTarget(spec, target, destination, manifestHash, options);
    assert.equal(receipt.assets_verified, true); assert.equal(receipt.payloads_verified, true); assert.equal(receipt.manifest_sha256, manifestHash);
    assert.deepEqual(receipt.product_sources, {cli: sha, runtime: sha});
    assert.equal(receipt.harness_sha, process.env.GITHUB_SHA ?? null);
    assert.equal(receipt.workflow_sha, receipt.harness_sha);
    assert.equal(receipt.full_passed, false); assert.equal(receipt.g1Passed, false); assert.deepEqual(receipt.actual_processes, []);
    assert.equal(receipt.assets.length, 5); assert.ok(receipt.remaining.includes('actual running image digests'));
    assert.equal(receipt.runtime_producer.metadata_sha256,spec.runtime.assets[0].sha256);
    assert.equal(receipt.runtime_producer.run_attempt,2);assert.equal(receipt.runtime_producer.artifacts.length,2);
    assert.deepEqual(JSON.parse(readFileSync(path.join(destination, 'published-assets-receipt.json'))), receipt);
    const inspected=path.join(destination,'inspected/runtime'),licensePath=path.join(inspected,'core-notices/CORE-SDK-LICENSE.txt');
    writeFileSync(licensePath,'tampered');assert.throws(()=>verifyCorePayload(inspected,target,sdk,runtime.files),/hash\/size/);writeFileSync(licensePath,license);
    writeFileSync(path.join(inspected,'unexpected'),'extra');assert.throws(()=>verifyCorePayload(inspected,target,sdk,runtime.files),/Runtime\/Core inventory/);rmSync(path.join(inspected,'unexpected'));
    assert.throws(()=>verifyCorePayload(inspected,target,{...sdk,sdk_version:'1.0.2-dev.22'}),/Core identity/);
    const consumed=await consumePublishedTarget(spec,target,destination,path.join(root,'nested/consumer/release'),manifestHash,{fetcher});
    assert.deepEqual(consumed.env,{RSRS_ARTIFACT_SOURCE:'published-assets',RSRS_RUNTIME_BIN:path.resolve(root,'nested/consumer/release/runtime',runtime.binary_file),RSRS_PUBLISHED_RUNTIME_SHA256:fileHash,RSRS_PUBLISHED_RUNTIME_VERSION:version,RSRS_PUBLISHED_ASSETS_SHA256:manifestHash,RSRS_PUBLISHED_BUNDLE_SHA256:archiveHash,RSRS_PUBLISHED_RUNTIME_ARCHIVE:path.resolve(destination,'runtime',runtime.archive_file),RSRS_PUBLISHED_RUNTIME_METADATA:path.resolve(destination,'runtime',`runtime-build-${target}.json`),RSRS_PUBLISHED_RUNTIME_METADATA_SHA256:hash(Buffer.from(JSON.stringify(runtime))),RSRS_RUNTIME_TRIPLE:target});
    assert.equal(hash(readFileSync(consumed.env.RSRS_RUNTIME_BIN)),fileHash);
    await assert.rejects(verifyPublishedTarget(spec, target, destination, manifestHash, options), /EEXIST/);
    producer.report.run_attempt='1';
    producer.replaceZip(1,[[`runtime-smoke-${target}.json`,JSON.stringify(producer.report)]]);
    const staleProducer=path.join(root,'stale-producer');
    await assert.rejects(verifyPublishedTarget(spec,target,staleProducer,manifestHash,options),/native report\/source\/attempt\/bytes/);
    const rejectedProducer=JSON.parse(readFileSync(path.join(staleProducer,'published-assets-receipt.json')));
    assert.equal(rejectedProducer.assets_verified,false);assert.equal(rejectedProducer.full_passed,false);
    corrupt = true;
    const failed = path.join(root, 'failed');
    await assert.rejects(verifyPublishedTarget(spec, target, failed, manifestHash, options), /hash\/size/);
    const failure = JSON.parse(readFileSync(path.join(failed, 'published-assets-receipt.json')));
    assert.equal(failure.assets_verified, false); assert.equal(failure.full_passed, false);
    assert.match(failure.error, /hash\/size/); assert.deepEqual(failure.actual_processes, []);
  } finally { rmSync(root, {recursive: true, force: true}); }
});

function syntheticTar(entries) {
  const blocks=[];
  for(const [name,content,type='0'] of entries) {
    const bytes=Buffer.from(content), header=Buffer.alloc(512);
    header.write(name,0,100); header.write('0000755\0',100); header.write('0000000\0',108); header.write('0000000\0',116);
    header.write(bytes.length.toString(8).padStart(11,'0')+'\0',124); header.write('00000000000\0',136);
    header.fill(32,148,156); header.write(type,156); header.write('ustar\0',257);
    const checksum=[...header].reduce((a,b)=>a+b,0); header.write(checksum.toString(8).padStart(6,'0')+'\0 ',148);
    blocks.push(header,bytes,Buffer.alloc((512-bytes.length%512)%512));
  }
  return gzipSync(Buffer.concat([...blocks,Buffer.alloc(1024)]));
}
test('published archive extractor refuses links, traversal, duplicates, bad checksums and truncated payloads',async()=>{
  const root=mkdtempSync(path.join(tmpdir(),'published-tar-test-'));
  try {
    const good=path.join(root,'good.tgz');writeFileSync(good,syntheticTar([['nested/file',Buffer.from('value')]]));
    await extractPublishedArchive(good,path.join(root,'good'));assert.equal(readFileSync(path.join(root,'good/nested/file'),'utf8'),'value');
    let i=0;
    for(const entries of [[['../escape','x']],[['/absolute','x']],[['dir/link','', '2']],[['hard','', '1']],[['device','', '3']],[['file','a'],['FILE','b']],[['dir/CON.txt','x']],[['dir./file','x']]]) {
      const file=path.join(root,`bad-${i}.tgz`);writeFileSync(file,syntheticTar(entries));await assert.rejects(extractPublishedArchive(file,path.join(root,`out-${i++}`)));
    }
    const damaged=gunzipSync(readFileSync(good));damaged[0]^=1;writeFileSync(path.join(root,'checksum.tgz'),gzipSync(damaged));
    await assert.rejects(extractPublishedArchive(path.join(root,'checksum.tgz'),path.join(root,'checksum')),/checksum/);
    const long='nested/'+ 'a'.repeat(120),extended=path.join(root,'long.tgz');
    writeFileSync(extended,syntheticTar([['././@LongLink',long+'\0','L'],['placeholder','long value']]));
    await extractPublishedArchive(extended,path.join(root,'long'));assert.equal(readFileSync(path.join(root,'long',long),'utf8'),'long value');
    writeFileSync(path.join(root,'truncated.tgz'),readFileSync(good).subarray(0,25));
    await assert.rejects(extractPublishedArchive(path.join(root,'truncated.tgz'),path.join(root,'truncated')));
  } finally {rmSync(root,{recursive:true,force:true});}
});
test('published compatibility checks exact product pin and numeric DEV minCLI without rebuilding',()=>{
  const spec={cli:{version:'1.0.21-dev.5'},runtime:{version:'1.0.21-dev.4'}};
  const runtime={compat:{min_cli:'1.0.21-dev.5',max_cli:'*'}}, pin={required:spec.runtime.version,accept:'>=1.0.21-dev.4,<2.0.0'};
  validatePublishedCompatibility(spec,runtime,pin);
  for(const bad of [{required:'1.0.21-dev.3'}, {accept:'*'}])assert.throws(()=>validatePublishedCompatibility(spec,runtime,{...pin,...bad}));
  for(const compat of [{min_cli:'1.0.21-dev.6',max_cli:'*'},{min_cli:'1.0.21-dev.5',max_cli:'1.0.21-dev.5'},{min_cli:'invalid',max_cli:'*'}])assert.throws(()=>validatePublishedCompatibility(spec,{compat},pin));
  validatePublishedCompatibility({...spec,cli:{version:'1.0.21-dev.10'}},runtime,pin);
});

function publishedFullFixture(root) {
  const targets=m.targets.map(t=>t.triple), manifestHash='d'.repeat(64), context={sha:'e'.repeat(40),run_id:901,run_attempt:2};
  const runtimeTargets=Object.keys(JSON.parse(readFileSync(new URL('../../runtime-tests-source.json',import.meta.url))).targets);
  let id=1;
  const spec={schema:2,...Object.fromEntries(['cli','runtime'].map(kind=>[kind,{repository:`risense-ai/respire-${kind}`,version:kind==='cli'?'1.0.21-dev.5':'1.0.21-dev.4',source_sha:(kind==='cli'?'a':'b').repeat(40),release_id:kind==='cli'?21:22,producer:{run_id:91,run_attempt:2},assets:(kind==='cli'?targets:runtimeTargets).flatMap(target=>publishedAssetNames(kind,target).map(name=>({id:id++,name,size:64,sha256:(kind==='cli'?'a':'b').repeat(64)})))}]))};
  const jobs=[];
  const job=name=>jobs.push({name,status:'completed',conclusion:'success',run_id:context.run_id,run_attempt:context.run_attempt,head_sha:context.sha});
  function put(artifact,file,value) {const location=path.join(root,artifact,file);mkdirSync(path.dirname(location),{recursive:true});writeFileSync(location,JSON.stringify(value));}
  const identity={source_sha:spec.cli.source_sha,version:spec.cli.version,binary_sha256:'a'.repeat(64)};
  const process={manifest_sha256:manifestHash,bundle_sha256:'b'.repeat(64),image_sha256:'b'.repeat(64),exe:'/isolated/runtime',pid:42,process_start_id:'synthetic-birth',installation_root:'/isolated',data_dir:'/isolated/profile',account_id:'account',instance_id:'instance',generation:1,protocol_v:1};
  const runtime={...identity,passed:true,runtime_mode:'standalone_runtime',standalone_runtime_evidence:true,runtime_binary_sha256:'b'.repeat(64),runtime_version:spec.runtime.version,runtime_identity_receipts:[process]};
  for(const target of targets) {
    job(`validate / Release (${target})`);job(`native-regression / Native (${target})`);
    const runtime_producer={...spec.runtime.producer,source_sha:spec.runtime.source_sha,target,metadata_sha256:'b'.repeat(64),
      binary_sha256:'b'.repeat(64),archive_sha256:'b'.repeat(64),artifacts:['runtime-release-','runtime-smoke-'].map((prefix,i)=>({id:31+i,job_id:11+i,name:prefix+target,zip_sha256:'c'.repeat(64)}))};
    put('published-assets-verification-'+target,'published-assets-receipt.json',{assets_verified:true,payloads_verified:true,target,manifest_sha256:manifestHash,harness_sha:context.sha,run_id:String(context.run_id),run_attempt:String(context.run_attempt),product_sources:{cli:spec.cli.source_sha,runtime:spec.runtime.source_sha},releases:Object.fromEntries(['cli','runtime'].map(kind=>[kind,{...spec[kind],assets:undefined}])),runtime_producer,assets:['cli','runtime'].flatMap(kind=>spec[kind].assets.filter(a=>a.name.includes(target)).map(a=>({repository:spec[kind].repository,...a})))});
    put('resident-concurrency-'+target,'real-account-return-verification.json',[runtime]);
    put('resident-concurrency-'+target,'resident-stress-metrics.json',{passed:true});
    put('resident-concurrency-'+target,'fixture-dependencies.json',{synthetic:true});
    put('resident-concurrency-'+target,'fixture-process-verification.json',[{passed:true}]);
    put('published-upgrades-'+target,'published-upgrades.json',{passed:true,profile:'critical',full_coverage:false,all_published_sources_covered:false,target,candidate_sha256:identity.binary_sha256,published_formal_sources:['v1.0.19','v1.0.20'],selected_sources:['v1.0.20'],sources:[{version:'1.0.20',formal:true,passed:true}]});
    put('published-upgrades-'+target,'v1.0.20/results/real-account-return-verification.json',[runtime]);
    if(target==='x86_64-unknown-linux-gnu')continue;
    job(`cloud-sweep (runner, ${target})`);
    put('base-release-sweep-'+target,'coverage.json',{...identity,observed_version:spec.cli.version,expected_version:spec.cli.version,base_complete:true,failed:0,required_missing:[]});
    if(target.includes('linux')) {
      put('release-sweep-'+target,'combined-coverage.json',{...identity,complete:true});
      put('release-sweep-'+target,'suite-results.json',['outbox','ai_inject','runtime','legacy_vault','profile_migration','login_interruption'].map(suite=>({suite,passed:true,exit:0})));
      for(const name of ['ai-inject-coverage.json','legacy-vault-coverage.json','migration-coverage.json','interruption-coverage.json'])put('release-sweep-'+target,name,{...identity,passed:true});
      for(const name of ['outbox-coverage.json','runtime-coverage.json'])put('release-sweep-'+target,name,runtime);
      put('secret-service-profile-migration-'+target,'migration-platform-gate.json',{...identity,passed:true});
      put('secret-service-profile-migration-'+target,'interruption-coverage.json',{...identity,passed:true});
    } else {
      job(`Native migration (${target})`);job(`Migration gate (${target})`);
      put('native-profile-migration-'+target,'migration-platform-gate.json',{...identity,complete:true});
    }
  }
  put('gnu-login-interruption','interruption-coverage.json',{...identity,passed:true});
  job('validate / npm-dry-run');job('api-smoke');
  const packageManifest=JSON.parse(readFileSync(new URL('../artifact-manifest.json',import.meta.url)));
  const packages=[...packageManifest.targets.map(t=>t.pkg),packageManifest.npmScope].map((name,i)=>{
    const file=`synthetic-${i}.tgz`,bytes=Buffer.from(`synthetic package ${i}`);
    mkdirSync(path.join(root,'npm-release-packages'),{recursive:true});writeFileSync(path.join(root,'npm-release-packages',file),bytes);
    return {name,version:spec.cli.version,file,sha256:createHash('sha256').update(bytes).digest('hex')};
  });
  put('npm-release-packages','published-package-validation.json',{artifact_source:'published-assets',harness_sha:context.sha,manifest_sha256:manifestHash,product_sources:{cli:spec.cli.source_sha,runtime:spec.runtime.source_sha},run_id:context.run_id,run_attempt:context.run_attempt,packages});

  const apiReports={};
  for(const name of ['dev-api-coverage.json','dev-github-api-coverage.json']) {
    put('dev-api-coverage',name,{complete:true,...(name==='dev-api-coverage.json'?{cli_workflow_sha:context.sha}:{} )});
    apiReports[name]=createHash('sha256').update(readFileSync(path.join(root,'dev-api-coverage',name))).digest('hex');
  }
  put('dev-api-coverage','published-api-identity.json',{harness_sha:context.sha,manifest_sha256:manifestHash,run_id:context.run_id,run_attempt:context.run_attempt,reports:apiReports});
  return {spec,targets,manifestHash,context,jobs,put,runtime};
}
test('published full joins every existing report and live image identity; copied summaries and partial jobs cannot pass',()=>{
  const root=mkdtempSync(path.join(tmpdir(),'published-full-join-'));
  try {
    const f=publishedFullFixture(root),run=()=>validatePublishedFull(f.spec,f.targets,f.manifestHash,root,f.jobs,f.context);
    const complete=run();assert.equal(complete.full_passed,true);assert.equal(complete.harness_sha,f.context.sha);
    assert.notEqual(complete.harness_sha,complete.product_sources.cli);
    assert.equal(complete.actual_processes.length,2*f.targets.length+2*f.targets.filter(t=>t.includes('linux')&&t!=='x86_64-unknown-linux-gnu').length);
    for(const change of [j=>j.pop(),j=>j.push(j[0]),j=>j[0].conclusion='skipped',j=>j[0].conclusion='cancelled',j=>j[0].conclusion='failure',j=>j[0].status='in_progress',j=>j[0].run_attempt=1,j=>j[0].head_sha=f.spec.cli.source_sha,j=>j[0].run_id=900]) {
      const jobs=copy(f.jobs);change(jobs);assert.throws(()=>validatePublishedFull(f.spec,f.targets,f.manifestHash,root,jobs,f.context));
    }
    const first=f.targets[0],artifact='resident-concurrency-'+first,file='real-account-return-verification.json';
    const producerReceipt=path.join(root,'published-assets-verification-'+first,'published-assets-receipt.json');
    const originalReceipt=readFileSync(producerReceipt);
    for(const kind of ['cli','runtime'])for(const field of ['run_id','run_attempt']){
      const changed=JSON.parse(originalReceipt);changed.releases[kind].producer[field]++;
      writeFileSync(producerReceipt,JSON.stringify(changed));assert.throws(run,/producer identity/);
    }
    for(const change of [r=>delete r.runtime_producer,r=>r.runtime_producer.run_attempt++,r=>r.runtime_producer.run_id++,
      r=>r.runtime_producer.source_sha='f'.repeat(40),r=>r.runtime_producer.target='other',r=>r.runtime_producer.metadata_sha256='f'.repeat(64),
      r=>r.runtime_producer.archive_sha256='f'.repeat(64),r=>r.runtime_producer.binary_sha256='f'.repeat(64),r=>r.runtime_producer.artifacts.pop()]) {
      const changed=JSON.parse(originalReceipt);change(changed);writeFileSync(producerReceipt,JSON.stringify(changed));
      assert.throws(run,/Runtime producer byte binding/);
    }
    writeFileSync(producerReceipt,originalReceipt);
    for(const change of [r=>r.passed=false,r=>r.runtime_mode='explicit_cli_shim',r=>r.standalone_runtime_evidence=false,r=>r.runtime_binary_sha256='c'.repeat(64),r=>r.runtime_version='1.0.21-dev.3',r=>r.runtime_identity_receipts=[],r=>r.runtime_identity_receipts[0].pid=0,r=>delete r.runtime_identity_receipts[0].process_start_id,r=>r.runtime_identity_receipts[0].protocol_v=2,r=>delete r.runtime_identity_receipts[0].account_id,r=>r.runtime_identity_receipts[0].image_sha256='c'.repeat(64),r=>r.runtime_identity_receipts[0].bundle_sha256='c'.repeat(64),r=>r.runtime_identity_receipts[0].manifest_sha256='c'.repeat(64)]) {
      const row=copy(f.runtime);change(row);f.put(artifact,file,[row]);assert.throws(run);f.put(artifact,file,[f.runtime]);
    }
    for(const [folder,name] of [['release-sweep-'+f.targets.find(t=>t.includes('linux')&&t!==first),'outbox-coverage.json'],['published-upgrades-'+first,'v1.0.20/results/real-account-return-verification.json'],['dev-api-coverage','published-api-identity.json'],['published-assets-verification-'+first,'published-assets-receipt.json']]) {
      const location=path.join(root,folder,name),bytes=readFileSync(location);rmSync(location);assert.throws(run);writeFileSync(location,bytes);
    }
    assert.equal(run().full_passed,true);
  } finally {rmSync(root,{recursive:true,force:true});}
});

test('published pack adapter retains version, repository, launcher, optional dependencies and SDK license assertions',()=>{
  const manifest={cliVersion:version,npmScope:'rsrs-cli',targets:[{pkg:'@rsrsai/linux-x64'}]};
  const launcher={name:manifest.npmScope,version,repository:{url:'https://github.com/risense-ai/respire-cli.git'},license:'SEE LICENSE IN LICENSE',bin:{rsrs:'./bin/cli.js'},optionalDependencies:{'@rsrsai/linux-x64':version}};
  const native={name:'@rsrsai/linux-x64',version,repository:launcher.repository,license:launcher.license};
  const files=new Set(['LICENSE','bin/core-notices/CORE-SDK-LICENSE.txt']),core={redistribution:'permitted-under-included-license'};
  validatePublishedPackage(launcher,manifest,launcher.name,null,files);validatePublishedPackage(native,manifest,native.name,core,files);
  for(const mutate of [p=>p.name='other',p=>p.version='1.0.0',p=>p.repository.url='https://foreign/repo.git',p=>p.dependencies={},p=>p.bin={other:'./bin/cli.js'},p=>p.optionalDependencies={},p=>p.license='MIT']) {
    const pkg=copy(launcher);mutate(pkg);assert.throws(()=>validatePublishedPackage(pkg,manifest,launcher.name,null,files));
  }
  for(const bad of [new Set(),new Set(['LICENSE','LICENSE-MIT-LEGACY']),new Set(['LICENSE'])])assert.throws(()=>validatePublishedPackage(native,manifest,native.name,core,bad));
  assert.throws(()=>validatePublishedPackage(native,manifest,native.name,{redistribution:'forbidden'},files));
  const frontend={...manifest,artifactLayout:'cli-frontend-v2'},frontendFiles=new Set(['LICENSE','bin/rsrs']);
  validatePublishedPackage(native,frontend,native.name,null,frontendFiles);
  validatePublishedPackage(launcher,frontend,launcher.name,null,new Set(['LICENSE','bin/cli.js']));
  assert.throws(()=>validatePublishedPackage(native,frontend,native.name,core,frontendFiles));
  assert.throws(()=>validatePublishedPackage(native,frontend,native.name,null,files));
  assert.throws(()=>validatePublishedPackage(native,frontend,native.name,null,new Set(['bin/rsrs'])));
});

test('official Runtime CI fixture retries only exact pinned metadata or paired archive network failures', async () => {
  const pin = JSON.parse(readFileSync(new URL('../../runtime-pin.json', import.meta.url), 'utf8'));
  const target = 'x86_64-unknown-linux-gnu';
  const url = `https://github.com/risense-ai/respire-runtime/releases/download/v${pin.required}/runtime-build-${target}.json`;
  const prefix = `release metadata request failed (${url}): ${url}: `;
  const envelope = error => ({command: 'cli', status: 'fail', summary: {reason: 'runtime_error'},
    items: [], actions: [], errors: [error], details: {error_type: 'runtime'}, related: []});
  const result = doc => ({status: 1, signal: null, stdout: Buffer.from(JSON.stringify(doc)), stderr: Buffer.from('first attempt diagnostics\n')});
  const readTimeout = 'Network Error: Network Error: Error encountered in the status line: timed out reading response: Network Error: Error encountered in the status line: timed out reading response: timed out reading response';
  const win = 'A connection attempt failed because the connected party did not properly respond after a period of time, or established connection failed because connected host has failed to respond. (os error 10060)';
  const connectTimeout = `Network Error: Network Error: Error encountered in the status line: ${win}: Network Error: Error encountered in the status line: ${win}: ${win}`;
  const exercise = async (first, expectedCalls, second = {status: 0, stdout: Buffer.from('{}'), stderr: Buffer.alloc(0)}) => {
    let calls = 0; const waits = [], output = [], errors = []; const env = {RSRS_DATA_DIR: 'isolated-fixture'};
    const actual = await installPinnedRuntime('fixture-cli', {env}, target, {
      spawn(cli, args, options) {
        calls++; assert.equal(cli, 'fixture-cli'); assert.deepEqual(args, ['--json', 'runtime', 'install']);
        assert.equal(options.env, env); assert.deepEqual(options.stdio, ['inherit', 'pipe', 'pipe']);
        return calls === 1 ? first : second;
      },
      pause: async ms => { waits.push(ms); },
      stdout: {write: bytes => output.push(Buffer.from(bytes))},
      stderr: {write: bytes => errors.push(Buffer.from(bytes))},
    });
    assert.equal(calls, expectedCalls); assert.deepEqual(waits, expectedCalls === 2 ? [2000] : []);
    assert.equal(actual, expectedCalls === 2 ? second : first);
    assert.deepEqual(output[0], first.stdout); assert.deepEqual(errors[0], first.stderr);
  };
  for (const reason of ['status code 429', 'status code 502', 'status code 503', 'status code 504', readTimeout, connectTimeout]) {
    await exercise(result(envelope(prefix + reason)), 2);
  }
  const first = result(envelope(prefix + 'status code 503'));
  await exercise(first, 2, first); // A second transient failure must stop after two attempts.
  const archive = url.replace(/\/runtime-build-([^/]+)\.json$/, '/rsrs-runtime-$1.tar.gz');
  const originFailure = (origin, reason) => {
    const asset = archive.replace('https://github.com', origin);
    return `${origin}: download failed (${asset}): ${asset}: ${reason}`;
  };
  const pair = [originFailure('https://github.com', 'status code 502'), originFailure('https://gh-proxy.com/https://github.com', readTimeout)];
  const aggregate = entries => 'runtime download failed: ' + entries.join('; ');
  await exercise(result(envelope(aggregate(pair))), 2);
  for (const entries of [[pair[0]], [...pair].reverse(), [...pair, pair[0]],
    [pair[0], pair[1].replace(readTimeout, 'archive checksum failed')],
    [pair[0].replace(`v${pin.required}/`, 'v0.0.0/'), pair[1]],
    [pair[0], pair[1].replace(target, 'aarch64-unknown-linux-gnu')],
    [pair[0], pair[1].replace(readTimeout, 'Permission denied (os error 13)')]]) await exercise(result(envelope(aggregate(entries))), 1);
  for (const error of [prefix + 'status code 401', prefix + 'status code 403', prefix + 'status code 404',
    prefix + 'status code 500', prefix + 'status code 503; archive checksum failed',
    prefix.replace('https://github.com/', 'https://evil.invalid/') + 'status code 503',
    prefix.replace(`v${pin.required}/`, 'v0.0.0/') + 'status code 503',
    prefix.replace(target, 'aarch64-unknown-linux-gnu') + 'status code 503',
    'runtime download failed: https://github.com: archive checksum failed; https://gh-proxy.com: status code 503',
    'invalid runtime release metadata', 'archive checksum failed', 'Permission denied (os error 13)']) {
    await exercise(result(envelope(error)), 1);
  }
  for (const mutate of [d => d.errors.push(prefix + 'status code 503'), d => d.details = {},
    d => d.summary.reason = 'other', d => d.command = 'runtime', d => d.status = 'ok',
    d => d.items.push({error: 'schema'}), d => d.schema = 2]) {
    const doc = envelope(prefix + 'status code 503'); mutate(doc); await exercise(result(doc), 1);
  }
  await exercise({...first, stdout: Buffer.from('not JSON')}, 1);
  await exercise({...first, error: new Error('spawn failed')}, 1);
  await exercise({...first, signal: 'SIGTERM'}, 1);
  await exercise({...first, status: 2}, 1);
  await exercise({...first, status: 0}, 1);
});
