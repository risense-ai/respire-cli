"""Matched published-binary CPU benchmark. CI-owned synthetic vaults only."""
import base64
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
import tarfile
import time
import urllib.request

import psutil
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from native_fixture_process import verify_runtime_health

ROOT = pathlib.Path(os.environ['PERF_ROOT']).resolve()
MODEL = pathlib.Path(os.environ['PERF_MODEL']).resolve()
TARGET = os.environ['PERF_TARGET']
VERSIONS = {'cli': '2.0.0-dev.3', 'baseline': '2.0.0-dev.8'}
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
          'order': ['baseline', 'candidate', 'candidate', 'baseline'],
          'cold_scope': 'first recall after model probe; fresh Runtime and lexical cache',
          'response_comparison': 'exact complete envelope except summary.query_log_id; raw retained',
          'results': [], 'complete': False}


def save():
    (ROOT / 'report.json').write_text(json.dumps(REPORT, indent=2), encoding='utf-8')


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def api(path):
    return json.loads(subprocess.check_output(['gh', 'api', path], timeout=60))


def published(role, inventory):
    version = VERSIONS[role]
    expected = inventory[role]
    repo = 'risense-ai/respire-' + ('cli' if role == 'cli' else 'runtime')
    source = expected['source_sha']
    assert len(source) == 40 and all(c in '0123456789abcdef' for c in source)
    producer = api(f'repos/{repo}/actions/runs/{int(expected["producer_run_id"])}')
    assert (producer['head_sha'] == source and producer['conclusion'] == 'success'
            and producer['path'] == '.github/workflows/release.yml'
            and producer['event'] in ('workflow_dispatch', 'push'))
    release = api(f'repos/{repo}/releases/tags/v{version}')
    assert not release['draft'] and release['tag_name'] == 'v' + version
    assert api(f'repos/{repo}/commits/v{version}')['sha'] == source
    assets = {asset['name']: asset for asset in release['assets']}
    folder = ROOT / ('assets-' + role)
    folder.mkdir()
    metadata_name = ('cli' if role == 'cli' else 'runtime') + '-build-' + TARGET + '.json'
    subprocess.run(['gh', 'release', 'download', 'v' + version, '--repo', repo,
                    '--pattern', metadata_name, '--dir', str(folder)], check=True, timeout=180)
    metadata_hash = digest(folder / metadata_name)
    assert metadata_hash == expected['metadata_sha256'][TARGET]
    assert assets[metadata_name]['digest'] == 'sha256:' + metadata_hash
    meta = json.loads((folder / metadata_name).read_text(encoding='utf-8'))
    if role == 'cli':
        assert meta['version'] == version and meta['target'] == TARGET and meta['git_sha'] == source
        names = [(meta['binary_file'], meta['binary_sha256']),
                 (meta['runtime_file'], meta['runtime_sha256'])]
    else:
        assert (meta['schema_version'] == 2 and meta['runtime_version'] == version
                and meta['target_triple'] == TARGET and meta['source_commit'] == source)
        names = [(meta['archive_file'], meta['archive_sha256'])]
        lock = api(f'repos/{repo}/contents/sdk/core-sdk.lock.json?ref={source}')
        lock_bytes = base64.b64decode(lock['content'])
        crate_lock = api(f'repos/{repo}/contents/crates/core-sdk/core-sdk.lock.json?ref={source}')
        assert json.loads(lock_bytes) == json.loads(base64.b64decode(crate_lock['content']))
        sdk = json.loads(lock_bytes)['targets'][TARGET]
        assert sdk['sdk_version'] == expected['sdk_version']
        if role == 'baseline':
            assert sdk['sdk_version'] == '2.0.0-dev.1'
    for name, expected_hash in names:
        assert pathlib.PurePosixPath(name).name == name and '\\' not in name
        subprocess.run(['gh', 'release', 'download', 'v' + version, '--repo', repo,
                        '--pattern', name, '--dir', str(folder)], check=True, timeout=300)
        assert digest(folder / name) == expected_hash
        assert assets[name]['digest'] == 'sha256:' + expected_hash
    destination = folder / 'unpacked'
    if role == 'cli':
        with tarfile.open(folder / meta['runtime_file']) as archive:
            archive.extractall(destination, filter='data')
        binary = destination / ('rsrs.exe' if os.name == 'nt' else 'rsrs')
        binary.write_bytes((folder / meta['binary_file']).read_bytes())
    else:
        with tarfile.open(folder / meta['archive_file']) as archive:
            archive.extractall(destination, filter='data')
        for item in meta['files']:
            path = destination / item['path']
            assert path.resolve().is_relative_to(destination.resolve()) and not path.is_symlink()
            assert path.stat().st_size == item['size'] and digest(path) == item['sha256']
        binary = destination / meta['binary_file']
        assert digest(binary) == meta['binary_sha256']
    binary.chmod(0o755)
    proof = {'version': version, 'source_sha': source, 'producer_run_id': producer['id'],
             'release_id': release['id'], 'metadata_sha256': metadata_hash,
             'assets': {name: {'id': assets[name]['id'], 'sha256': sha} for name, sha in names}}
    return binary, meta, folder, proof


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
                'status': envelope.get('status'), 'error_codes': [e.get('code') for e in envelope.get('errors', [])],
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
                                       **metric, 'response': envelope})
            assert metric['ok'] and envelope['items'], 'recall failed or returned no fixture source'
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
        assert set(inventory) == {'cli', 'baseline', 'candidate'}
        candidate = inventory['candidate']['version']
        assert candidate.startswith('2.0.0-dev.') and candidate.removeprefix('2.0.0-dev.').isdecimal()
        assert int(candidate.removeprefix('2.0.0-dev.')) > 8
        VERSIONS['candidate'] = candidate
        assert all(inventory[role]['version'] == version for role, version in VERSIONS.items())
        REPORT['release_inventory_sha256'] = os.environ['PERF_RELEASE_INVENTORY_SHA256']
        releases = {role: published(role, inventory) for role in VERSIONS}
        for role, release in releases.items():
            release[3]['role'] = role
        REPORT['provenance'] = {role: release[3] for role, release in releases.items()}
        binary = releases['cli'][0]
        prepare_model()
        env, port = environment(ROOT / 'fixture', binary, releases['baseline'])
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
            groups = {role: [run for run in runs if run['role'] == role] for role in ('baseline', 'candidate')}
            cold = {role: statistics.median(run['cold'] for run in group) for role, group in groups.items()}
            warm = {role: statistics.median(run['warm']['p50_seconds'] for run in group) for role, group in groups.items()}
            p95 = {role: statistics.median(run['warm']['p95_seconds'] for run in group) for role, group in groups.items()}
            settled = {role: statistics.median(request['settled_seconds'] for run in group for request in run['requests'][1:])
                       for role, group in groups.items()}
            REPORT['comparisons'][mode] = {'complete_responses_equal': True,
                'cold_median_seconds': cold, 'warm_p50_median_seconds': warm,
                'warm_p95_median_seconds': p95, 'warm_settled_median_seconds': settled,
                'candidate_over_baseline_warm_p95': p95['candidate'] / p95['baseline'],
                'candidate_over_baseline_settled': settled['candidate'] / settled['baseline'],
                'candidate_over_baseline_cold': cold['candidate'] / cold['baseline'],
                'candidate_over_baseline_warm': warm['candidate'] / warm['baseline'],
                'warm_observation': 'lower latency observed' if warm['candidate'] < warm['baseline'] else 'no lower latency observed'}
            save()
        REPORT['complete'] = True
    finally:
        save()
