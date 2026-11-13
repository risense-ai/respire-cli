"""Matched published-binary CPU benchmark. CI-owned synthetic vaults only."""
import copy
import hashlib
import hmac
import json
import math
import os
import pathlib
import platform
import secrets
import shutil
import socket
import sqlite3
import statistics
from types import SimpleNamespace
import subprocess
import time
import urllib.request

import psutil
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from native_fixture_process import verify_runtime_health

ROOT = pathlib.Path(os.environ['PERF_ROOT']).resolve()
MODEL = pathlib.Path(os.environ['PERF_MODEL']).resolve()
TARGET = os.environ['PERF_TARGET']
VERSIONS = {'cli': '2.0.0-dev.3'}
DOCUMENTS = ['Performance fixture document %03d. ' % i +
             ('Background indexing and foreground memory retrieval. ' * 24) +
             ' Unique topic number %03d.' % i for i in range(64)]
REPORT = {'versions': VERSIONS, 'target': TARGET, 'engine': 'cpu',
          'dataset_sha256': hashlib.sha256('\n'.join(DOCUMENTS).encode()).hexdigest(),
          'documents': len(DOCUMENTS), 'requests_per_batch': 24,
          'latency_scope': 'client-only CLI process and loopback RPC end-to-end',
          'percentile_method': 'nearest rank; successful requests only',
          'settled_scope': 'request plus normal heat persistence, including read-only polling overhead',
          'hardware': {'platform': platform.platform(), 'cpu': platform.processor(),
                       'logical_cpus': psutil.cpu_count(), 'memory_bytes': psutil.virtual_memory().total},
          'order': ['candidate'] * 4,
          'cold_scope': 'first recall after model probe; fresh Runtime and lexical cache',
          'response_comparison': 'exact complete envelope except summary.query_log_id; raw retained',
          'results': [], 'complete': False}


def save():
    (ROOT / 'report.json').write_text(json.dumps(REPORT, indent=2), encoding='utf-8')


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def published(inventory):
    # Reuse the release consumer's schema, metadata, download and bounded extraction contracts.
    subprocess.run(['node', '--input-type=module', '-e', r'''
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {mkdirSync, readFileSync, writeFileSync} from 'node:fs';
import {join, resolve} from 'node:path';
import {parsePublishedAssets, publishedAssetNames, inspectPublishedRelease,
  downloadPublishedAsset, validatePublishedMetadata, inspectRuntimeProducer,
  consumePublishedTarget} from './npm/scripts/extract-artifact.mjs';
const env = process.env, root = resolve(env.PERF_ROOT), target = env.PERF_TARGET;
const manifest = JSON.parse(readFileSync('npm/artifact-manifest.json'));
const spec = parsePublishedAssets(env.PERF_RELEASE_INVENTORY, env.PERF_RELEASE_INVENTORY_SHA256,
  manifest.targets.map(row => row.triple));
assert.equal(spec.cli.version, '2.0.0-dev.3');
assert.match(spec.runtime.version, /^2\.0\.0-dev\.\d+$/);
assert(Number(spec.runtime.version.split('.').at(-1)) >= 10);
assert(manifest.targets.some(row => row.triple === target));
const api = path => JSON.parse(execFileSync('gh', ['api', '--hostname', 'github.com', 'repos/' + path],
  {encoding:'utf8', timeout:60000, maxBuffer:2 ** 21, windowsHide:true}));
const destination = join(root, 'published-assets');
mkdirSync(destination);
const receipt = {schema:2, manifest_sha256:env.PERF_RELEASE_INVENTORY_SHA256,
  target, releases:{}, assets:[], complete:false};
try {
  for (const kind of ['cli', 'runtime']) {
    const part = spec[kind];
    receipt.releases[kind] = {repository:part.repository, version:part.version,
      ...await inspectPublishedRelease(part, {token:env.GH_TOKEN}),
      producer_workflow:'.github/workflows/release.yml'};
    const directory = join(destination, kind); mkdirSync(directory);
    for (const name of publishedAssetNames(kind, target)) {
      const asset = part.assets.find(row => row.name === name);
      await downloadPublishedAsset(part, asset, directory, {token:env.GH_TOKEN});
      receipt.assets.push({repository:part.repository, ...asset});
    }
  }
  const metadata = kind => JSON.parse(readFileSync(join(destination, kind, kind + '-build-' + target + '.json')));
  validatePublishedMetadata(spec, target, metadata('cli'), metadata('runtime'));
  receipt.runtime_producer = await inspectRuntimeProducer(spec.runtime, target, {token:env.GH_TOKEN});
  const lock = path => JSON.parse(Buffer.from(api(spec.runtime.repository + '/contents/' + path
    + '?ref=' + spec.runtime.source_sha).content, 'base64'));
  assert.deepEqual(lock('sdk/core-sdk.lock.json'), lock('crates/core-sdk/core-sdk.lock.json'));
  const consumed = await consumePublishedTarget(spec, target, destination, join(root, 'verified'),
    env.PERF_RELEASE_INVENTORY_SHA256, {token:env.GH_TOKEN});
  receipt.payload_identity = consumed.identity;
  receipt.complete = true;
} finally {
  writeFileSync(join(root, 'published-assets-receipt.json'), JSON.stringify(receipt, null, 2) + '\n');
}
'''], check=True, timeout=900)
    receipt = json.loads((ROOT / 'published-assets-receipt.json').read_text(encoding='utf-8'))
    assert receipt['complete'] and receipt['manifest_sha256'] == os.environ['PERF_RELEASE_INVENTORY_SHA256']
    REPORT['published_assets'] = receipt
    releases = {}
    for role, kind in (('cli', 'cli'), ('candidate', 'runtime')):
        part = inventory[kind]
        folder = ROOT / 'published-assets' / kind
        meta = json.loads((folder / (kind + '-build-' + TARGET + '.json')).read_text(encoding='utf-8'))
        binary = (ROOT / 'verified' / ('rsrs.exe' if os.name == 'nt' else 'rsrs') if role == 'cli'
                  else ROOT / 'verified' / 'runtime' / meta['binary_file'])
        proof = {**receipt['releases'][kind], 'role': role,
                 'metadata_sha256': digest(folder / (kind + '-build-' + TARGET + '.json')),
                 'assets': {asset['name']: {'id': asset['id'], 'sha256': asset['sha256']}
                            for asset in receipt['assets'] if asset['repository'] == part['repository']}}
        releases[role] = binary, meta, folder, proof
    return releases


def install_runtime(binary, env, release):
    _, meta, folder, _ = release
    completed = subprocess.run([str(binary), '--json', 'runtime', 'install', '--file',
        str(folder / meta['archive_file']), '--version', meta['runtime_version']],
        env=env, capture_output=True, timeout=180)
    assert completed.returncode == 0, 'official offline Runtime install failed'
    profile = pathlib.Path(env['RSRS_DATA_DIR'])
    assert profile.resolve().is_relative_to(ROOT) and not profile.is_symlink()
    receipt = json.loads((profile / 'runtime.json').read_text(encoding='utf-8'))
    metadata = folder / ('runtime-build-' + TARGET + '.json')
    assert receipt['version'] == meta['runtime_version'] and receipt['sha256'] == meta['binary_sha256']
    assert receipt['release']['metadata_sha256'] == digest(metadata)
    assert receipt['release']['metadata_json'].encode() == metadata.read_bytes()
    installed = profile / 'runtime' / meta['runtime_version'] / ('rsrs-runtime.exe' if os.name == 'nt' else 'rsrs-runtime')
    assert digest(installed) == meta['binary_sha256']
    env['RSRS_RUNTIME_BIN'] = str(installed)
    return installed


def environment(root, binary, release):
    profile = root / '.rsrs'
    profile.mkdir(parents=True, mode=0o700)
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(('RSRS_', 'ONEMEMORY_', 'RESPIRE_'))
           and k not in ('GH_TOKEN', 'GITHUB_TOKEN', 'CORE_SDK_READ_TOKEN')}
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    env.update(HOME=str(root), USERPROFILE=str(root), RSRS_DATA_DIR=str(profile), RSRS_RPC_PORT=str(port),
               RSRS_NO_AUTOSYNC='1', RSRS_UPDATE_CHECK='0', RSRS_M3_DIR=str(MODEL), RSRS_ENGINE='cpu',
               RSRS_RUNTIME_TRIPLE=TARGET, RSRS_LANG='en', LC_ALL='C',
               XDG_CONFIG_HOME=str(root / 'config'), XDG_DATA_HOME=str(root / 'share'),
               XDG_CACHE_HOME=str(root / 'cache'), APPDATA=str(root / 'appdata'),
               LOCALAPPDATA=str(root / 'local'), RSRS_BIN_DIR=str(root / 'bin'))
    # Install with release proof before creating the synthetic account session.
    install_runtime(binary, env, release)
    entropy, salt, nonce, urk = secrets.token_bytes(18), secrets.token_bytes(16), secrets.token_bytes(12), secrets.token_bytes(32)
    code = 'A3-' + '-'.join(entropy.hex().upper()[i:i + 6] for i in range(0, 36, 6))
    kek = hmac.new(hmac.new(salt, entropy, hashlib.sha256).digest(), b'onememory:kek:v4\x01', hashlib.sha256).digest()
    (profile / 'session.json').write_text(json.dumps({'user': 'synthetic-performance', 'vault_version': 4,
        'kdf_salt': salt.hex(), 'wrapped_urk': AESGCM(kek).encrypt(nonce, urk, None).hex(), 'urk_nonce': nonce.hex()}), encoding='utf-8')
    (profile / 'client.json').write_text(json.dumps({'addr': 'https://fixture.invalid', 'autosync': False,
        'data_dir': str(profile), 'service_mode': 'normal'}), encoding='utf-8')
    env['RSRS_SUPER'] = code
    return env, port


def request(binary, env, args, direct=False):
    start = time.perf_counter()
    try:
        completed = subprocess.run([str(binary), '--json', '--direct' if direct else '--client-only', *args],
                                   env=env, capture_output=True, timeout=300 if direct else 60)
        try:
            envelope = json.loads(completed.stdout)
        except (ValueError, UnicodeError):
            envelope = {}
        ok = completed.returncode == 0 and envelope.get('status') in ('ok', 'warn')
        return {'seconds': time.perf_counter() - start, 'ok': ok, 'exit': completed.returncode,
                'status': envelope.get('status'), 'error_count': len(envelope.get('errors', [])),
                'items': len(envelope.get('items', []))}, envelope
    except subprocess.TimeoutExpired:
        return {'seconds': time.perf_counter() - start, 'ok': False, 'timeout': True}, {}


def required(binary, env, args, direct=False):
    metric, envelope = request(binary, env, args, direct)
    assert metric['ok'], {'command': args[0], 'metric': metric}
    return envelope


def ready(binary, env):
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        _, data = request(binary, env, ['doctor'])
        rows = {i['name']: i['status'] for i in data.get('items', []) if i['name'] in ('embedder', 'model index')}
        if len(rows) == 2 and all(v == 'ok' for v in rows.values()):
            return
        time.sleep(.5)
    raise RuntimeError('index readiness exceeded 600 seconds')


def batch(metrics):
    successful = sorted(m['seconds'] for m in metrics if m['ok'])
    percentile = lambda p: successful[max(0, math.ceil(p * len(successful)) - 1)] if successful else None
    return {'requests': len(metrics), 'successful': len(successful),
            'failed': len(metrics) - len(successful), 'wall_seconds': sum(m['seconds'] for m in metrics),
            'p50_seconds': percentile(.5), 'p95_seconds': percentile(.95),
            'max_seconds': max(successful) if successful else None, 'raw': metrics}


def prepare_model():
    for asset in ('onnx/model_quantized.onnx', 'tokenizer.json'):
        destination = MODEL / asset
        if not destination.exists():
            destination.parent.mkdir(parents=True, exist_ok=True)
            url = 'https://huggingface.co/Xenova/bge-m3/resolve/4de13258303883538bd53b696b452bf8099f0858/' + asset
            with urllib.request.urlopen(url, timeout=60) as response, destination.open('wb') as output:
                shutil.copyfileobj(response, output)
    for name, expected in {
        'onnx/model_quantized.onnx': '0826f8c1ab9edf1801db86c61919d4d108e8bfc0b809ec823ad366882ff0b77d',
        'tokenizer.json': '6710678b12670bc442b99edc952c4d996ae309a7020c1fa0096dd245c2faf790'}.items():
        assert digest(MODEL / name) == expected
    REPORT['model'] = {'name': 'BGE-M3 quantized', 'onnx_sha256': digest(MODEL / 'onnx/model_quantized.onnx')}


def stop(binary, env, worker=None):
    children = psutil.Process(worker.pid).children(recursive=True) if worker and worker.poll() is None else []
    try:
        subprocess.run([str(binary), '--runtime-internal', '--stop'], env=env,
                       capture_output=True, timeout=50, check=True)
    finally:
        if worker:
            if worker.poll() is None:
                worker.terminate()
            worker.wait(timeout=15)
            _, alive = psutil.wait_procs(children, timeout=10)
            assert not alive, 'owned inference descendants did not exit'


def start(binary, env, port, release, label):
    installed = install_runtime(binary, env, release)
    with (ROOT / (label + '-runtime.log')).open('wb') as log:
        worker = subprocess.Popen([str(installed), '--runtime-internal'], env=env, stdout=log, stderr=log)
    identity = SimpleNamespace(runtime_binary=installed, runtime_sha256=release[1]['binary_sha256'],
        runtime_version=release[1]['runtime_version'], runtime_identity_receipts=[])
    try:
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            assert worker.poll() is None, 'owned Runtime exited during startup'
            try:
                with urllib.request.urlopen(f'http://127.0.0.1:{port}/api/health', timeout=2) as response:
                    health = json.load(response)
                profile = pathlib.Path(env['RSRS_DATA_DIR'])
                verify_runtime_health(identity, health, profile, profile, pid=worker.pid)
                return worker
            except OSError:
                time.sleep(.1)
        raise RuntimeError('owned Runtime startup timeout')
    except BaseException:
        stop(binary, env, worker)
        raise


def heat(profile):
    with sqlite3.connect(f'file:{(profile / "rsrs.db").as_posix()}?mode=ro', uri=True) as db:
        return db.execute('SELECT id,recall_count FROM memories WHERE deleted=0 ORDER BY id').fetchall()


def normalized(envelope):
    output = copy.deepcopy(envelope)
    # This random durable-query identity is retained verbatim in the raw response.
    assert isinstance(output['summary']['query_log_id'], str)
    output['summary']['query_log_id'] = '<request-id>'
    return output


def benchmark(binary, release, mode, number, env, port, snapshot):
    profile = pathlib.Path(env['RSRS_DATA_DIR'])
    with sqlite3.connect(snapshot) as source, sqlite3.connect(profile / 'rsrs.db') as target:
        source.backup(target)
    result = {'role': release[3]['role'], 'version': release[1]['runtime_version'],
              'mode': mode, 'replay': number, 'requests': [], 'complete': False}
    REPORT['results'].append(result)
    worker = start(binary, env, port, release, mode + '-' + str(number))
    try:
        ready(binary, env)
        required(binary, env, ['model', 'probe', '--model', 'm3'])
        result['ready_rss_bytes'] = psutil.Process(worker.pid).memory_info().rss
        previous = heat(profile)
        command = ['recall', 'Background indexing foreground memory retrieval',
                   '--intent', 'auto', '--limit', '5']
        if mode == 'quality':
            command.extend(['--mode', mode])
        # Keep associations and full rendering; each measured response includes metadata evidence.
        for index in range(25):
            started = time.perf_counter()
            metric, envelope = request(binary, env, command)
            result['requests'].append({'phase': 'cold' if index == 0 else 'warm',
                                       **metric, 'response': envelope if metric['ok'] and not metric['error_count'] else None})
            assert metric['ok'] and not metric['error_count'] and envelope['items'], 'recall failed or returned no fixture source'
            assert envelope['summary']['metadata_aware'] is True
            assert envelope['summary']['recall_mode'] == mode
            normalized(envelope)
            deadline = time.monotonic() + 15
            while True:
                current = heat(profile)
                if sum(row[1] for row in current) > sum(row[1] for row in previous):
                    break
                assert time.monotonic() < deadline, 'normal heat writeback did not complete'
                time.sleep(.01)
            result['requests'][-1]['heat_after'] = current
            result['requests'][-1]['settled_seconds'] = time.perf_counter() - started
            previous = current
            save()
        result['cold'] = result['requests'][0]['seconds']
        result['warm'] = batch(result['requests'][1:])
        result['complete'] = True
    finally:
        stop(binary, env, worker)
        save()


if __name__ == '__main__':
    assert os.environ.get('GITHUB_ACTIONS') == 'true', 'benchmark is restricted to CI-owned fixtures'
    assert os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'
    owned = pathlib.Path(os.environ['RUNNER_TEMP']).resolve()
    assert ROOT != owned and ROOT.is_relative_to(owned) and MODEL.is_relative_to(owned)
    assert not ROOT.exists(), 'comparison directory must be fresh'
    ROOT.mkdir(mode=0o700)
    try:
        raw_inventory = os.environ['PERF_RELEASE_INVENTORY']
        assert hashlib.sha256(raw_inventory.encode()).hexdigest() == os.environ['PERF_RELEASE_INVENTORY_SHA256']
        inventory = json.loads(raw_inventory)
        comparison_mode = os.environ.get('PERF_COMPARISON_MODE', 'candidate-only')
        assert comparison_mode == 'candidate-only', 'this release gate permits candidate-only'
        assert inventory['schema'] == 2 and set(inventory) == {'schema', 'cli', 'runtime'}
        assert inventory['cli']['version'] == VERSIONS['cli']
        candidate = inventory['runtime']['version']
        assert candidate.startswith('2.0.0-dev.') and candidate.removeprefix('2.0.0-dev.').isdecimal()
        assert int(candidate.removeprefix('2.0.0-dev.')) >= 10
        REPORT['measurement_scope'] = 'single published candidate; cold/warm observations, no cross-version speedup claim'
        REPORT['cold_warm_consistency'] = 'same initial snapshot and matching phase/query-sequence position across candidate replays'
        REPORT['response_comparison'] = 'exact complete envelope at matching query-sequence positions across fresh snapshot replays except summary.query_log_id; raw retained'
        REPORT['comparison_mode'] = comparison_mode
        VERSIONS['candidate'] = candidate
        REPORT['release_inventory_sha256'] = os.environ['PERF_RELEASE_INVENTORY_SHA256']
        releases = published(inventory)
        REPORT['provenance'] = {role: release[3] for role, release in releases.items()}
        binary = releases['cli'][0]
        prepare_model()
        env, port = environment(ROOT / 'fixture', binary, releases['candidate'])
        fixture = ROOT / 'entries.json'
        # Fixed old dates avoid wall-clock decay drift; no expiry or asserted verification.
        fixture.write_text(json.dumps([{'title': 'document-%03d' % i, 'content': document,
            'kind': 'context', 'user': 'synthetic-performance', 'importance': 'important',
            'created_at': '2000-01-01T00:00:00.000Z', 'updated_at': '2000-01-01T00:00:00.000Z',
            'memory_contract': 1, 'summary': 'Synthetic metadata clue 🧪 é'}
            for i, document in enumerate(DOCUMENTS)]), encoding='utf-8')
        try:
            # Public metadata enable performs its normal backup and isolated-library admission.
            required(binary, env, ['metadata', 'enable'], direct=True)
            required(binary, env, ['model', 'engine', 'cpu'], direct=True)
            required(binary, env, ['model', 'activate', 'm3'], direct=True)
            seeded = required(binary, env, ['import', str(fixture)], direct=True)
            assert seeded['summary']['imported'] == len(DOCUMENTS)
            ready(binary, env)
        finally:
            if (pathlib.Path(env['RSRS_DATA_DIR']) / 'runtime/endpoint.json').exists():
                stop(binary, env)
        snapshot = ROOT / 'seed.sqlite'
        with sqlite3.connect(pathlib.Path(env['RSRS_DATA_DIR']) / 'rsrs.db') as source, sqlite3.connect(snapshot) as target:
            source.backup(target)
        REPORT['snapshot_sha256'] = digest(snapshot)
        REPORT['comparisons'] = {}
        for mode in ('fast', 'quality'):
            for number, role in enumerate(REPORT['order']):
                benchmark(binary, releases[role], mode, number, env, port, snapshot)
            runs = [run for run in REPORT['results'] if run['mode'] == mode]
            reference = runs[0]['requests']
            for run in runs[1:]:
                for index, (left, right) in enumerate(zip(reference, run['requests'], strict=True)):
                    assert normalized(left['response']) == normalized(right['response']), (mode, run['replay'], index, 'complete response changed')
                    assert left['heat_after'] == right['heat_after'], (mode, index, 'heat replay changed')
            groups = {role: [run for run in runs if run['role'] == role] for role in dict.fromkeys(REPORT['order'])}
            cold = {role: statistics.median(run['cold'] for run in group) for role, group in groups.items()}
            warm = {role: statistics.median(run['warm']['p50_seconds'] for run in group) for role, group in groups.items()}
            p95 = {role: statistics.median(run['warm']['p95_seconds'] for run in group) for role, group in groups.items()}
            settled = {role: statistics.median(request['settled_seconds'] for run in group for request in run['requests'][1:])
                       for role, group in groups.items()}
            REPORT['comparisons'][mode] = {'complete_responses_equal': True,
                'cold_median_seconds': cold, 'warm_p50_median_seconds': warm,
                'warm_p95_median_seconds': p95, 'warm_settled_median_seconds': settled}
            save()
        REPORT['complete'] = True
    finally:
        save()
