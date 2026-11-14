import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {appendFileSync, closeSync, existsSync, mkdirSync, openSync, readFileSync, realpathSync, writeFileSync} from 'node:fs';
import {join, resolve} from 'node:path';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';

const repository = 'risense-ai/respire-runtime';
const roles = {
  business_tests: 'RSRS_RUNTIME_TEST_RUNNER',
  app_tests: 'RSRS_RUNTIME_APP_TESTS',
  storage_tests: 'RSRS_RUNTIME_STORAGE_TESTS',
  feedback_contract_probe: 'RSRS_RUNTIME_FEEDBACK_PROBE',
  ablation_bench: 'RSRS_RUNTIME_ABLATION_BENCH',
};
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const json = file => JSON.parse(readFileSync(file, 'utf8'));
const digest = value => assert.match(value ?? '', /^[a-f0-9]{64}$/);
const id = value => assert(Number.isSafeInteger(value) && value > 0, 'Require a positive immutable GitHub ID');

export function readPin() {
  const pin = json('runtime-tests-source.json');
  assert.equal(pin.schema_version, 1);
  assert.equal(pin.repository, repository);
  assert.match(pin.source_sha ?? '', /^[a-f0-9]{40}$/);
  assert.equal(pin.producer?.status, 'ready', 'Runtime test bundle pins are pending; publish and review the producer receipt first');
  assert.match(pin.producer.workflow_sha ?? '', /^[a-f0-9]{40}$/);
  assert.equal(pin.producer.workflow, '.github/workflows/prebuilt-integration-tests.yml');
  for (const value of [pin.producer.workflow_id, pin.producer.run_id, pin.producer.run_attempt]) id(value);
  digest(pin.sdk_lock_sha256);
  const head = execFileSync('git', ['rev-parse', 'HEAD'], {encoding: 'utf8'}).trim();
  assert.match(head, /^[a-f0-9]{40}$/);
  for (const file of ['sdk/core-sdk.lock.json', 'crates/core-sdk/core-sdk.lock.json']) {
    const bytes = execFileSync('git', ['show', `${head}:${file}`]);
    assert.equal(sha256(bytes), pin.sdk_lock_sha256, 'The committed CLI SDK lock bytes differ from the bundle');
  }
  assert.deepEqual(pin.features, ['cpu-owned-ort-experiment']);
  assert.equal(pin.tests?.business?.length, 31);
  assert.equal(new Set(pin.tests.business).size, 31);
  for (const name of pin.tests.business) assert.match(name, /^[a-z_]+::[a-z_0-9]+$/);
  for (const requested of [process.env.REQUESTED_RUNTIME_SHA, process.env.RUNTIME_EXAMPLES_SHA]) {
    if (requested) assert.equal(requested, pin.source_sha, 'Runtime source overrides must equal the reviewed bundle source');
  }
  return pin;
}

function api(path) {
  return JSON.parse(execFileSync('gh', ['api', `repos/${repository}/${path}`],
    {encoding: 'utf8', timeout: 180_000, maxBuffer: 16 * 1024 * 1024}));
}

export function verifyOrigin(pin, target, run, workflow, artifact) {
  const producer = pin.producer, selected = pin.targets[target];
  assert(selected, `Missing Runtime bundle target ${target}`);
  id(selected.artifact_id);
  digest(selected.sha256);
  assert.equal(run.id, producer.run_id);
  assert.equal(run.run_attempt, producer.run_attempt);
  assert.equal(run.status, 'completed');
  assert.equal(run.conclusion, 'success');
  assert.equal(run.event, 'workflow_dispatch');
  assert.equal(run.head_branch, 'main');
  assert.equal(run.head_sha, producer.workflow_sha, 'Trusted workflow commit differs from the compiled Runtime source');
  assert.equal(run.repository?.full_name, repository);
  assert.equal(run.head_repository?.full_name, repository);
  assert.equal(run.workflow_id, producer.workflow_id);
  assert.equal(run.path, producer.workflow);
  assert.equal(workflow.id, producer.workflow_id);
  assert.equal(workflow.path, producer.workflow);
  assert.equal(artifact.id, selected.artifact_id);
  assert.equal(artifact.name, `runtime-test-bundle-${target}`);
  assert.equal(artifact.expired, false);
  assert.equal(artifact.workflow_run?.id, producer.run_id);
  assert.equal(artifact.workflow_run?.head_sha, producer.workflow_sha);
  assert.equal(artifact.workflow_run?.repository_id, run.repository.id);
  assert.equal(artifact.workflow_run?.head_repository_id, run.head_repository.id);
  assert.equal(artifact.digest, `sha256:${selected.sha256}`, 'The API must expose the exact pinned artifact digest');
}

// Python's ZIP reader handles CRC and ZIP64; extraction never follows archive paths or links.
const verifyFiles = String.raw`
import hashlib, json, os, re, shutil, stat, sys, tempfile, zipfile
archive, destination, mode = sys.argv[1:]
manifest_name = 'manifest.json'
def safe(name):
    assert isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9_./+-]+', name), 'Unsafe bundle path'
    parts = name.split('/')
    assert all(part not in ('', '.', '..') and not part.endswith(('.', ' ')) for part in parts), 'Unsafe bundle component'
    assert all(not re.fullmatch(r'(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?', part) for part in parts), 'Reserved bundle path'
    return name
def check(root, manifest):
    assert manifest['schema_version'] == 1
    expected = {manifest_name}
    folded = {manifest_name.casefold()}
    for item in manifest['files']:
        name = safe(item['path'])
        assert name.casefold() not in folded, 'Duplicate inventory path'
        expected.add(name); folded.add(name.casefold())
        assert type(item['size']) is int and item['size'] >= 0
        assert re.fullmatch(r'[a-f0-9]{64}', item['sha256'])
        path = os.path.join(root, *name.split('/'))
        assert stat.S_ISREG(os.lstat(path).st_mode), 'Bundle file is not regular'
        assert os.path.getsize(path) == item['size'], 'Bundle size mismatch'
        digest = hashlib.sha256()
        with open(path, 'rb') as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b''): digest.update(block)
        assert digest.hexdigest() == item['sha256'], 'Bundle digest mismatch'
    actual = set()
    for directory, dirs, files in os.walk(root, followlinks=False):
        assert all(not os.path.islink(os.path.join(directory, name)) for name in dirs + files), 'Bundle link rejected'
        actual.update(os.path.relpath(os.path.join(directory, name), root).replace(os.sep, '/') for name in files)
    assert actual == expected, 'Unlisted or missing bundle file'
    for name in manifest['roles'].values():
        assert safe(name) in expected - {manifest_name}, 'Role is missing from the inventory'
if mode == 'extract':
    assert not os.path.lexists(destination), 'Bundle destination must be fresh'
    parent = os.path.dirname(destination)
    os.makedirs(parent, exist_ok=True)
    assert not os.path.islink(parent), 'Bundle destination parent is a link'
    temporary = tempfile.mkdtemp(prefix='.runtime-bundle-', dir=parent)
    try:
        with zipfile.ZipFile(archive) as bundle:
            entries = {}
            for entry in bundle.infolist():
                name = safe(entry.filename[:-1] if entry.is_dir() else entry.filename)
                assert name.casefold() not in entries, 'Duplicate archive path'
                entries[name.casefold()] = entry
                kind = stat.S_IFMT(entry.external_attr >> 16)
                assert kind in (0, stat.S_IFREG, stat.S_IFDIR), 'Archive link or special file rejected'
                assert not entry.flag_bits & 1, 'Encrypted bundle rejected'
            entry = entries.get(manifest_name)
            assert entry and not entry.is_dir() and entry.file_size <= 1024 * 1024
            manifest = json.loads(bundle.read(entry))
            listed = {safe(item['path']) for item in manifest['files']} | {manifest_name}
            assert {entry.filename for entry in entries.values() if not entry.is_dir()} == listed, 'Archive inventory mismatch'
            for entry in entries.values():
                if entry.is_dir(): continue
                path = os.path.join(temporary, *entry.filename.split('/'))
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with bundle.open(entry) as source, open(path, 'xb') as output: shutil.copyfileobj(source, output)
            check(temporary, manifest)
            for name in manifest['roles'].values(): os.chmod(os.path.join(temporary, *name.split('/')), 0o755)
        os.rename(temporary, destination)
    finally:
        if os.path.exists(temporary): shutil.rmtree(temporary)
else:
    assert not os.path.islink(destination), 'Bundle root is a link'
    with zipfile.ZipFile(archive) as bundle: original = bundle.read(manifest_name)
    with open(os.path.join(destination, manifest_name), 'rb') as stream:
        assert stream.read() == original, 'Installed manifest differs from the pinned ZIP bytes'
    manifest = json.loads(original)
    check(destination, manifest)
    for name in manifest['roles'].values(): os.chmod(os.path.join(destination, *name.split('/')), 0o755)
`;

export function verifyManifest(pin, target, manifest) {
  assert.equal(manifest.schema_version, 1);
  assert.equal(manifest.repository, repository);
  assert.equal(manifest.source_sha, pin.source_sha);
  assert.equal(manifest.target, target);
  assert.equal(manifest.sdk_lock_sha256, pin.sdk_lock_sha256);
  assert.deepEqual(manifest.features, pin.features);
  assert.deepEqual(Object.keys(manifest.roles).sort(), Object.keys(roles).sort());
  assert.deepEqual([...manifest.tests.business].sort(), [...pin.tests.business].sort());
  assert.equal(new Set(manifest.tests.business).size, 31);
  const receipt = manifest.producer;
  assert(receipt, 'Missing trusted producer input receipt');
  for (const key of ['run_id', 'run_attempt', 'workflow_sha', 'workflow']) assert.equal(receipt[key], pin.producer[key]);
  assert.equal(receipt.source_sha, pin.source_sha);
}

async function main() {
  const [command, target, ...arguments_] = process.argv.slice(2);
  const pin = readPin();
  if (command === 'source') {
    assert(!target, 'source takes no target');
    assert(process.env.GITHUB_OUTPUT, 'GITHUB_OUTPUT is required');
    appendFileSync(process.env.GITHUB_OUTPUT, `sha=${pin.source_sha}\n`);
    return;
  }
  assert(command === 'fetch' || command === 'verify', 'Use source, fetch TARGET [DESTINATION], or verify TARGET [DESTINATION] --list');
  assert(pin.targets[target], 'Missing exact Runtime test target');
  id(pin.targets[target].artifact_id);
  digest(pin.targets[target].sha256);
  const destination = resolve(arguments_.find(argument => argument !== '--list') || join('.runtime-test-bundles', target));
  const archive = `${destination}.zip`, receiptFile = `${destination}.receipt.json`;
  if (command === 'fetch') {
    const run = api(`actions/runs/${pin.producer.run_id}/attempts/${pin.producer.run_attempt}`);
    const workflow = api(`actions/workflows/${pin.producer.workflow_id}`);
    const artifact = api(`actions/artifacts/${pin.targets[target].artifact_id}`);
    verifyOrigin(pin, target, run, workflow, artifact);
    assert(!existsSync(destination) && !existsSync(archive) && !existsSync(receiptFile), 'Refuse existing bundle output');
    mkdirSync(resolve(destination, '..'), {recursive: true});
    const fd = openSync(archive, 'wx');
    try {
      execFileSync('gh', ['api', `repos/${repository}/actions/artifacts/${artifact.id}/zip`],
        {stdio: ['ignore', fd, 'pipe'], timeout: 600_000});
    } finally { closeSync(fd); }
    assert.equal(sha256(readFileSync(archive)), pin.targets[target].sha256, 'Runtime bundle ZIP digest mismatch');
    execFileSync('python', ['-I', '-c', verifyFiles, archive, destination, 'extract'], {stdio: 'inherit'});
    const manifest = json(join(destination, 'manifest.json'));
    verifyManifest(pin, target, manifest);
    writeFileSync(receiptFile, JSON.stringify({schema_version: 1, repository, source_sha: pin.source_sha,
      target, producer: pin.producer, artifact_id: artifact.id, sha256: pin.targets[target].sha256,
      manifest_sha256: sha256(readFileSync(join(destination, 'manifest.json')))}, null, 2) + '\n', {flag: 'wx'});
  } else {
    assert.equal(sha256(readFileSync(archive)), pin.targets[target].sha256, 'Runtime bundle ZIP digest mismatch');
    const receipt = json(receiptFile);
    assert.equal(receipt.source_sha, pin.source_sha);
    assert.equal(receipt.target, target);
    assert.equal(receipt.artifact_id, pin.targets[target].artifact_id);
    assert.equal(receipt.sha256, pin.targets[target].sha256);
    assert.deepEqual(receipt.producer, pin.producer);
    assert.equal(sha256(readFileSync(join(destination, 'manifest.json'))), receipt.manifest_sha256);
    execFileSync('python', ['-I', '-c', verifyFiles, archive, destination, 'verify'], {stdio: 'inherit'});
  }
  const manifest = json(join(destination, 'manifest.json'));
  verifyManifest(pin, target, manifest);
  if (arguments_.includes('--list')) {
    const runner = realpathSync(join(destination, manifest.roles.business_tests));
    const output = execFileSync(runner, ['--list'], {encoding: 'utf8', timeout: 60_000});
    const names = output.split(/\r?\n/).filter(line => line.endsWith(': test')).map(line => line.slice(0, -6));
    assert.deepEqual(names.sort(), [...pin.tests.business].sort(), 'The executable must contain exactly the original 31 business assertions');
    for (const [role, key, filter] of [['app_tests', 'app', 'snapshot::tests::'],
      ['storage_tests', 'storage', 'transport::local::sync::diary_tests::']]) {
      const expected = manifest.tests[key];
      assert(Array.isArray(expected) && expected.length > 0, 'Runtime internal test filters cannot be empty');
      assert.equal(new Set(expected).size, expected.length);
      assert(expected.every(name => name.startsWith(filter)));
      const listing = execFileSync(realpathSync(join(destination, manifest.roles[role])), [filter, '--list'],
        {encoding: 'utf8', timeout: 60_000});
      const actual = listing.split(/\r?\n/).filter(line => line.endsWith(': test')).map(line => line.slice(0, -6));
      assert.deepEqual(actual.sort(), [...expected].sort(), 'The precompiled internal filter must retain every declared assertion');
    }
  }
  assert(process.env.GITHUB_ENV, 'GITHUB_ENV is required');
  const variables = Object.entries(roles).map(([role, variable]) => [variable, realpathSync(join(destination, manifest.roles[role]))]);
  variables.push(['RSRS_RUNTIME_BUNDLE_DIR', realpathSync(destination)],
    ['RSRS_RUNTIME_BUNDLE_RECEIPT', realpathSync(receiptFile)], ['RUNTIME_TESTS_SHA', pin.source_sha], ['RUNTIME_EXAMPLES_SHA', pin.source_sha]);
  for (const [name, value] of variables) {
    assert(!/[\r\n]/.test(value), 'Invalid environment path');
    appendFileSync(process.env.GITHUB_ENV, `${name}=${value}\n`);
  }
  console.log(`Verified Runtime test bundle ${target}: source ${pin.source_sha}, run ${pin.producer.run_id}/${pin.producer.run_attempt}, artifact ${pin.targets[target].artifact_id}`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(error => { console.error(`Runtime test bundle rejected: ${error.message}`); process.exitCode = 1; });
}
