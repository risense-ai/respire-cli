#!/usr/bin/env python3
"""Real unchanged Client2 v2.0.0-dev.5 host calls; account-free temporary installations.

Requires official CLI/Runtime bytes and an unmodified checkout of the pinned
Client2 source. Optional pinned Magpie source exercises its original legacy RPC.
This is not GUI, account, model-inference or G1 acceptance.
"""
import argparse
import hashlib
import json
import errno
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import tarfile
import time
import urllib.error
import urllib.request

CLIENT2_SHA = 'be682108c555a3e5a788ad74217e088bcb25170b'
MAGPIE_SHA = 'a3ae9b3035d02b181ba7a8ddae251495d092dd63'
MAGPIE_RUNTIME_BLOB = 'ac5de49cac36a2a6a697abb9a9529b2426a9ef49'
# Official Linux x64 desktop: Client2 dev.5, produced by run 43018703263.
DESKTOP_SOURCE_SHA = CLIENT2_SHA
DESKTOP_SHA256 = 'dc74596d983ab7b99c6b6872d8438cfb2f2e7060b93f9a9ef13db629b6a5d7a2'
DESKTOP_ARCHIVE_SHA256 = '69707b8a65df1f46e73b4ea5ddc33235c861a0870f8d0260f261437228c7356a'

def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()

def annotate_failure(case):
    if os.environ.get('GITHUB_ACTIONS') != 'true':
        return
    # Only the current account-free fixture's errors. Do not copy files,
    # credentials, downloaded logs, or another run's evidence into annotations.
    message = json.dumps({'case': case['name'], 'failure': case.get('failure'),
                          'errors': case.get('errors'), 'cleanup_exit': case.get('cleanup_exit'),
                          'cleanup_error': case.get('cleanup_error')})
    message = message.replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')
    print(f'::error title=Client2 fixture failure::{message}', flush=True)

def coverage_profile(value):
    if value is None:
        return None
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'):
        raise RuntimeError('Coverage forwarding requires an isolated hosted runner')
    expected = Path(__file__).resolve().parents[1] / 'target' / 'llvm-cov-target'
    if expected.resolve(strict=True) != expected:
        raise RuntimeError('Coverage directory must not redirect outside the source workspace')
    template = Path(value)
    if not template.is_absolute() or template.parent.resolve(strict=True) != expected:
        raise RuntimeError('Coverage profile parent must be the current source coverage directory')
    plain_name = template.name.replace('%m', '').replace('%p', '')
    if ('%m' not in template.name or '%p' not in template.name
            or not template.name.endswith('.profraw')
            or not plain_name or any(not (char.isascii() and (char.isalnum() or char in '_.-'))
                                     for char in plain_name)):
        raise RuntimeError('Coverage profile must retain the process and module placeholders')
    return str(expected / template.name)


def desktop_executable(value):
    if value is None:
        return None
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'
            or sys.platform != 'linux' or os.uname().machine != 'x86_64'):
        raise RuntimeError('Pinned desktop acceptance requires an isolated Linux x64 hosted runner')
    path = value.resolve(strict=True)
    if not path.is_file() or sha256(path) != DESKTOP_SHA256:
        raise RuntimeError('Require the exact released Client2 v2.0.0-dev.5 Linux x64 desktop bytes')
    return path


def linux_runtime_record(pid):
    if type(pid) is not int or pid <= 0 or pid == os.getpid():
        raise RuntimeError('Invalid desktop Runtime PID')
    return Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()


def verify_desktop_runtime(health, root, image, port):
    pid = health['pid']
    before = linux_runtime_record(pid)
    assert before[0] != 'Z'
    assert health['process_start_id'] == 'linux-starttime-' + before[19]
    assert health['server'] == 'respire' and health['v'] == 1
    assert Path(health['installation_root']).resolve(strict=True) == root
    assert Path(health['data_dir']).resolve(strict=True).is_relative_to(root)
    assert Path(health['exe']).resolve(strict=True) == image
    assert Path(health['image_path']).resolve(strict=True) == image
    assert Path(f'/proc/{pid}/exe').resolve(strict=True) == image
    assert health['image_sha256'] == sha256(image)
    # Bind the reported PID to the actual IPv4 loopback listening socket.
    sockets = set()
    for fd in Path(f'/proc/{pid}/fd').iterdir():
        try:
            sockets.add(os.readlink(fd))
        except FileNotFoundError:
            continue  # Other Runtime workers may close unrelated descriptors during inspection.
    listeners = [line.split() for line in Path('/proc/net/tcp').read_text().splitlines()[1:]]
    assert any(row[1] == f'0100007F:{port:04X}' and row[3] == '0A'
               and f'socket:[{row[9]}]' in sockets for row in listeners)
    after = linux_runtime_record(pid)
    assert after[0] != 'Z' and after[19] == before[19]
    return {key: health[key] for key in ['pid', 'installation_id', 'instance_id',
            'process_start_id', 'image_sha256', 'runtime_version', 'account_id', 'generation']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cli', type=Path, required=True)
    parser.add_argument('--runtime-archive', type=Path, required=True)
    parser.add_argument('--runtime-version', required=True)
    parser.add_argument('--client2-source', type=Path, required=True)
    parser.add_argument('--go', type=Path, required=True)
    parser.add_argument('--magpie-source', type=Path)
    parser.add_argument('--node', type=Path)
    parser.add_argument('--desktop-executable', type=Path,
                        help='Hosted CI only: released Client2 v2.0.0-dev.5 Linux x64 desktop executable')
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--go-mod-cache', type=Path)
    parser.add_argument('--offline', action='store_true')
    parser.add_argument('--ordinary-cli-cold-start', action='store_true',
                        help='Also verify ordinary CLI status cold-start before original Client2 reuse')
    parser.add_argument('--coverage-profile-file', help='Hosted CI only: existing instrumented CLI profile template')
    args = parser.parse_args()
    profile = coverage_profile(args.coverage_profile_file)
    desktop = desktop_executable(args.desktop_executable)
    cli, archive, source, go = (p.resolve(strict=True) for p in
                                [args.cli, args.runtime_archive, args.client2_source, args.go])
    def git(*argv):
        return subprocess.check_output(['git', '-C', str(source), *argv], text=True).strip()
    if git('rev-parse', 'HEAD') != CLIENT2_SHA or git('status', '--porcelain'):
        raise RuntimeError('Require unchanged Client2 v2.0.0-dev.5 source')
    magpie = args.magpie_source.resolve(strict=True) if args.magpie_source else None
    node = None
    if magpie:
        def magpie_git(*argv):
            return subprocess.check_output(['git', '-C', str(magpie), *argv], text=True).strip()
        if (magpie_git('rev-parse', 'HEAD') != MAGPIE_SHA or magpie_git('status', '--porcelain')
                or magpie_git('hash-object', 'runtime.mjs') != MAGPIE_RUNTIME_BLOB):
            raise RuntimeError('Require unchanged released Magpie v0.3.16 source')
        node_path = args.node or shutil.which('node')
        if not node_path:
            raise RuntimeError('Original Magpie RPC probe requires Node.js')
        node = Path(node_path).resolve(strict=True)
        if not node.is_file():
            raise RuntimeError('Original Magpie RPC probe requires a Node.js executable')
    elif args.node:
        raise RuntimeError('--node requires --magpie-source')
    base = Path(tempfile.mkdtemp(prefix='client2-launcher-regression-')).resolve()
    probe = base / 'probe'; probe.mkdir()
    (probe / 'go.mod').write_text('module respire-client2/regression\n\ngo 1.26.0\n\n'
        'require respire-client2 v0.0.0\nreplace respire-client2 => ' + json.dumps(str(source)) + '\n')
    shutil.copyfile(source / 'go.sum', probe / 'go.sum')
    for fixture in (Path(__file__).parent / 'fixtures/client2-v0256-probe').glob('*.go'):
        shutil.copyfile(fixture, probe / fixture.name)
    executable = probe / ('probe.exe' if os.name == 'nt' else 'probe')
    build_env = {k: os.environ[k] for k in ['PATH', 'SystemRoot', 'WINDIR', 'TEMP', 'TMP', 'COMSPEC', 'PATHEXT'] if k in os.environ}
    build_env.update(GOPATH=str(base / 'go-path'), GOCACHE=str(base / 'go-cache'), GOMODCACHE=str(args.go_mod_cache.resolve(strict=True) if args.go_mod_cache else base / 'go-mod'))
    if args.offline: build_env['GOPROXY'] = 'off'
    subprocess.run([str(go), 'build', '-buildvcs=false', '-mod=mod', '-o', str(executable), '.'],
                   cwd=probe, env=build_env, check=True, timeout=300)
    report = {'client2_source': CLIENT2_SHA, 'coverage': 'real-host-process-no-accounts',
              'g1_passed': False, 'root': str(base), 'cases': [],
              'inputs': {'cli_sha256': sha256(cli), 'runtime_archive_sha256': sha256(archive),
                         'runtime_version': args.runtime_version,
                         'ordinary_cli_cold_start': args.ordinary_cli_cold_start,
                         'coverage_profile_file': profile},
              'desktop_headless': {'enabled': desktop is not None, 'client2_source': DESKTOP_SOURCE_SHA,
                                   'release': 'v2.0.0-dev.5', 'run_id': '43018703263',
                                   'asset_id': 735418491, 'archive_sha256': DESKTOP_ARCHIVE_SHA256,
                                   'binary_sha256': DESKTOP_SHA256 if desktop else None},
              'legacy_plugin': {'executed': magpie is not None,
                                'source_sha': MAGPIE_SHA if magpie else None,
                                'runtime_blob': MAGPIE_RUNTIME_BLOB if magpie else None},
              'excluded': ['desktop GUI', 'accounts and credentials', 'model inference',
                           'managed services', 'cross-platform execution'] + ([] if magpie else ['original plugin RPC'])}
    def run(argv, env):
        # Go/Rust emit UTF-8, including Chinese errors. Decode captured bytes
        # explicitly instead of using Windows' locale-dependent text reader.
        with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
            result = subprocess.run([str(x) for x in argv], env=env, stdout=output,
                                    stderr=errors, timeout=150)
            output.seek(0); errors.seek(0)
            result.stdout = output.read(8 * 1024 * 1024 + 1).decode('utf-8', errors='replace')
            result.stderr = errors.read(8 * 1024 * 1024 + 1).decode('utf-8', errors='replace')
            if len(result.stdout) > 8 * 1024 * 1024 or len(result.stderr) > 8 * 1024 * 1024:
                raise RuntimeError('Fixture process output exceeded 8 MiB')
            return result
    def helper_result(result):
        if not result.stdout:
            raise RuntimeError(f'Client2 helper returned no JSON: exit={result.returncode}, stderr={result.stderr[:2000]}')
        return json.loads(result.stdout)
    def request(port, path, body=None, headers=None, raw=False):
        request = urllib.request.Request(f'http://127.0.0.1:{port}{path}',
            data=None if body is None else json.dumps(body).encode(),
            headers={'Content-Type': 'application/json', **(headers or {})})
        # Never inherit proxy settings or replay a failed request.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            response = opener.open(request, timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            data = response.read(8 * 1024 * 1024 + 1)
            if len(data) > 8 * 1024 * 1024: raise RuntimeError('Oversized boundary response')
            if raw: return response.code, data
            try: value = json.loads(data)
            except json.JSONDecodeError: value = None
            return response.code, value
    def boundaries(port):
        results = {}
        for name, headers in [('foreign_host', {'Host': 'foreign.invalid'}),
                              ('foreign_origin', {'Origin': 'http://foreign.invalid'})]:
            status, _ = request(port, '/api/health', headers=headers)
            results[name] = status
            if status != 403: raise RuntimeError(f'{name} was not rejected: HTTP {status}')
        base = {'v': 1, 'id': 'compat-boundary', 'method': 'cli.exec', 'args': ['--json', 'status']}
        status, _ = request(port, '/api/rpc', {**base, 'operation_id': 'mixed-identity'})
        results['mixed_identity'] = status
        if status != 400: raise RuntimeError(f'Mixed legacy/modern identity was not rejected: HTTP {status}')
        status, health = request(port, '/api/health', headers={'X-Respire-Health': 'runtime-v1'})
        if status != 200 or not health: raise RuntimeError('Modern health is unavailable')
        scope = {key: health[key] for key in ['account_id', 'instance_id', 'generation']}
        scope['instance_id'] = 'foreign-instance'
        status, result = request(port, '/api/rpc', {**base, 'scope': scope,
            'operation_id': 'wrong-scope', 'idempotency_key': 'wrong-scope'})
        results['wrong_scope'] = result.get('code') if result else None
        if status != 200 or not result or result.get('ok') is not False or result.get('code') != 'scope_mismatch':
            raise RuntimeError('Wrong scope was not rejected without rebinding')
        return results
    def mcp_read(port):
        status, health = request(port, '/api/health', headers={'X-Respire-Health': 'runtime-v1'})
        assert status == 200
        scope = {key: health[key] for key in ['account_id', 'instance_id', 'generation']}
        def call(method, params=None):
            body = {'jsonrpc': '2.0', 'id': 'compat-'+method, 'method': method, 'params': params or {}}
            status, reply = request(port, '/mcp', body)
            assert status == 200 and reply['jsonrpc'] == '2.0' and reply['id'] == body['id'], reply
            assert 'error' not in reply, reply
            return reply['result']
        initialized = call('initialize', {'protocolVersion': '2025-03-26', 'capabilities': {},
            'clientInfo': {'name': 'client2-host-regression', 'version': '1'}})
        assert initialized['serverInfo']['name'] == 'respire-runtime'
        assert initialized['serverInfo']['version'] == args.runtime_version
        listed = call('tools/list')
        assert 'memory_status' in [tool['name'] for tool in listed['tools']]
        result = call('tools/call', {'name': 'memory_status', 'arguments': {}})
        assert result['isError'] is False
        envelope = json.loads(result['content'][0]['text'])
        assert envelope['command'] == 'status' and envelope['status'] == 'ok' and envelope['errors'] == []
        assert envelope['scope'] == scope
        assert envelope['memory_context']['memory_text_authority'] == 'untrusted_historical_context'
        for path in ['/mcp', '/sse']:
            status, body = request(port, path, headers={'Accept': 'text/event-stream'}, raw=True)
            assert status == 200 and body == f'event: endpoint\ndata: http://127.0.0.1:{port}/mcp\n\n'.encode()
        return {'initialize': True, 'tools_list': True, 'real_status': True, 'public_sse_endpoint': True}
    def desktop_action(action, env):
        result = run([desktop, '--headless', action], env)
        payload = helper_result(result)
        if result.returncode != 0 or payload.get('ok') is not True:
            raise RuntimeError(f'Original desktop {action} failed: ' + json.dumps(payload))
        assert set(payload) == {'ok', 'result', 'task'}
        return payload['result']
    modes = ['client2-owned', 'external-cli-cold-start', 'reuse-cli-started']
    if args.ordinary_cli_cold_start:
        modes.append('reuse-cli-business-started')
    if desktop:
        modes.append('desktop-owned')
    if os.name == 'posix':
        modes.append('cli-host-sigterm')
    if sys.platform in ['linux', 'darwin']:
        modes.append('cli-host-sigkill')
    if sys.platform == 'darwin':
        modes.append('cli-guardian-sigkill')
    if os.name == 'nt':
        modes.append('cli-host-terminate')
    for mode in modes:
        root = base / mode; root.mkdir(); home = root / 'home'; home.mkdir()
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0)); port = listener.getsockname()[1]
        env = {k: os.environ[k] for k in ['PATH', 'SystemRoot', 'WINDIR', 'TEMP', 'TMP', 'COMSPEC', 'PATHEXT'] if k in os.environ}
        env.update(HOME=str(home), USERPROFILE=str(home), RSRS_DATA_DIR=str(root), RSRS_BIN_DIR=str(root/'bin'),
                   RSRS_RPC_PORT=str(port), RSRS_CORE_TEST_MODE='1', RSRS_NO_AUTOSYNC='1', RSRS_UPDATE_CHECK='0', RSRS_LANG='en')
        if profile is not None:
            env['LLVM_PROFILE_FILE'] = profile
        for key, name in [('XDG_CONFIG_HOME','config'),('XDG_DATA_HOME','share'),('XDG_CACHE_HOME','cache'),
                          ('XDG_STATE_HOME','state'),('XDG_RUNTIME_DIR','run'),('APPDATA','appdata'),('LOCALAPPDATA','local')]:
            path = root / name; path.mkdir(); env[key] = str(path)
        case = {'name': mode, 'passed': False}; report['cases'].append(case)
        try:
            installed = run([cli, '--json', 'runtime', 'install', '--file', archive, '--version', args.runtime_version], env)
            if installed.returncode: raise RuntimeError('Official Runtime installation failed: '+installed.stderr)
            selection = json.loads((root/'bin/runtime.json').read_text())
            (root/'bin').mkdir(exist_ok=True)
            shutil.copy2(cli, root/'bin'/('rsrs.exe' if os.name=='nt' else 'rsrs'))
            if mode in ['client2-owned', 'desktop-owned']:
                destination = root/'client2/runtime'/args.runtime_version
                shutil.copytree(root/'bin/runtime'/args.runtime_version, destination)
                # The unchanged legacy Client2 requires notices from the CLI-verified archive.
                with tarfile.open(archive, 'r:gz') as packaged:
                    notices = [entry for entry in packaged.getmembers()
                               if entry.name == 'core-notices' or entry.name.startswith('core-notices/')]
                    packaged.extractall(destination, members=notices, filter='data')
                (root/'client2/runtime.json').write_text(json.dumps({'version':args.runtime_version,'sha256':selection['sha256']}))
            if mode == 'reuse-cli-started':
                started = run([cli, '--json', 'runtime', 'start'], env)
                if started.returncode: raise RuntimeError('CLI startup failed: '+started.stderr)
            if mode == 'desktop-owned':
                env['RSRS_INSTANCE_ID'] = base.name + '-' + mode
                version = run([desktop, '--version'], env)
                if version.returncode or helper_result(version) != {
                        'version': '2.0.0-dev.5', 'platform': 'linux-amd64'}:
                    raise RuntimeError('Pinned original desktop version identity changed')
                desktop_action('start', env)
                health = desktop_action('status', env)
                assert health['runtime_version'] == args.runtime_version
                image = (destination / 'rsrs-runtime').resolve(strict=True)
                identity = verify_desktop_runtime(health, root, image, port)
                reply = desktop_action('rpc-status', env)
                assert reply['v'] == 1 and isinstance(reply['id'], str) and reply['id']
                assert reply['ok'] is True and reply['exit'] == 0
                assert reply['envelope']['command'] == 'status'
                assert reply['envelope']['status'] == 'ok' and reply['envelope']['errors'] == []
                assert Path(reply['envelope']['summary']['data_dir']).resolve(strict=True) == Path(health['data_dir']).resolve(strict=True)
                desktop_action('start', env)
                assert verify_desktop_runtime(desktop_action('status', env), root, image, port) == identity
                case['desktop_headless'] = {'cold_start': True, 'status': True, 'rpc_status': True,
                                            'reused_same_runtime': True, 'verified_identity': identity}
            if mode == 'reuse-cli-business-started':
                started = run([cli, '--json', 'status'], env)
                case['ordinary_cli_start_exit'] = started.returncode
                if started.returncode:
                    raise RuntimeError('Ordinary CLI business cold-start failed: ' + started.stderr)
                # --json renders ResultEnvelope directly; helper_result only decodes JSON.
                initial_status = helper_result(started)
                assert initial_status['command'] == 'status' and initial_status['status'] == 'ok'
                assert initial_status['errors'] == []
                code, initial_health = request(port, '/api/health', headers={'X-Respire-Health': 'runtime-v1'})
                assert code == 200 and initial_health['runtime_version'] == args.runtime_version
                assert Path(initial_health['installation_root']).resolve() == root
                assert initial_health['image_sha256'] == selection['sha256']
                identity_keys = ['pid', 'instance_id', 'process_start_id', 'image_sha256',
                                 'runtime_version', 'account_id', 'generation', 'installation_root', 'data_dir']
                case['ordinary_cli_start_identity'] = {key: initial_health[key] for key in identity_keys}
            result = run([executable, 'start'], env)
            payload = helper_result(result)
            case['client2_exit'] = result.returncode
            case['errors'] = {k:v for k,v in payload.items() if k.endswith('_error')}
            case['legacy_rpc_ok'] = payload.get('diagnostic_rpc',{}).get('ok')
            case['legacy_rpc_code'] = payload.get('diagnostic_rpc',{}).get('code')
            if mode == 'reuse-cli-business-started':
                code, reused_health = request(port, '/api/health', headers={'X-Respire-Health': 'runtime-v1'})
                assert code == 200
                assert {key: reused_health[key] for key in identity_keys} == case['ordinary_cli_start_identity']
                case['ordinary_cli_actor_preserved'] = True
            if result.returncode or case['legacy_rpc_ok'] is not True:
                raise RuntimeError('Unmodified Client2 startup/business calls failed')
            case['boundaries'] = boundaries(port)
            case['mcp'] = mcp_read(port)
            if magpie:
                original_plugin = run([node, Path(__file__).parent / 'fixtures/client2-v0256-probe/magpie-rpc.mjs',
                                       magpie, f'http://127.0.0.1:{port}/'], env)
                if original_plugin.returncode:
                    raise RuntimeError('Original Magpie RPC failed: ' + original_plugin.stderr[:2000])
                plugin_result = helper_result(original_plugin)
                expected_plugin = {'passed': True, 'original_rpc': True, 'legacy_projection_verified': True,
                                   'same_actor_before_after': True, 'same_runtime': True}
                if plugin_result != expected_plugin:
                    raise RuntimeError('Original Magpie RPC returned incomplete evidence')
                case['magpie_rpc'] = plugin_result
            host_operations = run([executable, 'host-operations'], env)
            host_result = helper_result(host_operations)
            checks = host_result.get('cases')
            required_host_operations = ['auth_register', 'auth_login', 'auth_recover', 'auth_reset', 'inject_targets']
            if (set(host_result) != {'passed', 'cases'} or type(host_result['passed']) is not bool
                    or not isinstance(checks, list) or [check.get('name') for check in checks] != required_host_operations
                    or any(set(check) != {'name', 'passed', 'terminal_envelope', 'repeated_id_stable'}
                           or any(type(check[key]) is not bool for key in ['passed', 'terminal_envelope', 'repeated_id_stable'])
                           for check in checks)):
                raise RuntimeError('Original Client2 host-operation evidence is incomplete')
            case['host_operations'] = host_result
            if host_operations.returncode or not host_result['passed'] or not all(check['passed'] for check in checks):
                raise RuntimeError('Original Client2 host-operation protocol or terminal envelope failed')
            reused = run([cli, '--json', 'status'], dict(env, RSRS_NO_AUTOSTART='1'))
            case['cli_reuse_exit'] = reused.returncode
            if reused.returncode: raise RuntimeError('CLI cannot reuse Client2-compatible service')
            if mode in ['cli-host-sigterm', 'cli-host-sigkill', 'cli-host-terminate', 'cli-guardian-sigkill']:
                _, visible = request(port, '/api/health')
                _, backend = request(port, '/api/health', headers={'X-Respire-Health': 'runtime-v1'})
                assert visible['compatibility_host'] == 'client2-v0256'
                assert Path(visible['exe']).resolve() == (root / 'bin' / ('rsrs.exe' if os.name == 'nt' else 'rsrs')).resolve()
                assert Path(visible['installation_root']).resolve() == root.resolve()
                if mode == 'cli-host-terminate':
                    import ctypes
                    from ctypes import wintypes
                    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
                    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
                    kernel.OpenProcess.restype = wintypes.HANDLE
                    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
                    kernel.WaitForSingleObject.restype = wintypes.DWORD
                    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
                    handle = kernel.OpenProcess(0x00100000, False, backend['pid'])
                    assert handle, 'Cannot observe the owned backend process'
                    try:
                        os.kill(visible['pid'], signal.SIGTERM)
                        assert kernel.WaitForSingleObject(handle, 15000) == 0, 'Owned backend survived host termination'
                    finally:
                        kernel.CloseHandle(handle)
                elif mode == 'cli-guardian-sigkill':
                    guardian = int(subprocess.check_output(
                        ['ps', '-p', str(visible['pid']), '-o', 'ppid='], text=True).strip())
                    image = subprocess.check_output(['ps', '-p', str(guardian), '-o', 'comm='], text=True).strip()
                    assert guardian > 1 and Path(image).resolve() == Path(visible['exe']).resolve()
                    os.kill(guardian, signal.SIGKILL)
                else:
                    os.kill(visible['pid'], signal.SIGKILL if mode == 'cli-host-sigkill' else signal.SIGTERM)
                deadline = time.monotonic() + 90
                while time.monotonic() < deadline:
                    with socket.socket() as connection:
                        # Windows can take about two seconds to report a refused connection.
                        connection.settimeout(5)
                        if connection.connect_ex(('127.0.0.1', port)) == errno.ECONNREFUSED:
                            break
                    time.sleep(0.1)
                else:
                    raise RuntimeError('Signaled compatibility host did not close its listener')
                receipt_path = root / 'runtime' / f"stop-{backend['instance_id']}.json"
                if mode == 'cli-host-terminate':
                    assert not receipt_path.exists(), 'Forced cleanup must not claim a normal drain'
                    case['forced_backend_exit'] = True
                    case['signal_drained'] = False
                elif mode == 'cli-host-sigkill' and sys.platform == 'linux':
                    deadline = time.monotonic() + 15
                    stat = Path(f"/proc/{backend['pid']}/stat")
                    while time.monotonic() < deadline:
                        try:
                            fields = stat.read_text().rsplit(')', 1)[1].split()
                        except FileNotFoundError:
                            break
                        if fields[0] == 'Z':
                            break
                        assert backend['process_start_id'] == 'linux-starttime-' + fields[19]
                        time.sleep(0.05)
                    else:
                        raise RuntimeError('Owned backend survived compatibility host SIGKILL')
                    assert not receipt_path.exists(), 'Forced cleanup must not claim a normal drain'
                    case['forced_backend_exit'] = True
                    case['signal_drained'] = False
                else:
                    if sys.platform == 'darwin':
                        deadline = time.monotonic() + 90
                        while time.monotonic() < deadline:
                            observed = subprocess.run(['ps', '-p', str(backend['pid']), '-o', 'stat='],
                                                      capture_output=True, text=True, timeout=5)
                            assert observed.returncode in [0, 1], observed.stderr
                            state = observed.stdout.strip()
                            if not state or state.startswith('Z'):
                                break
                            time.sleep(0.1)
                        else:
                            raise RuntimeError('Owned backend survived macOS host/guardian termination')
                    receipt = json.loads(receipt_path.read_text())
                    for key in ['pid', 'instance_id', 'process_start_id', 'image_sha256', 'account_id']:
                        assert receipt[key] == backend[key], key
                    assert receipt['state'] == 'drained' and receipt['unfinished'] == []
                    case['signal_drained'] = True
                if args.ordinary_cli_cold_start:
                    # The original shutdown/receipt checks above must finish before recovery.
                    if sys.platform == 'linux':
                        deadline = time.monotonic() + 15
                        while time.monotonic() < deadline:
                            try:
                                fields = linux_runtime_record(backend['pid'])
                            except FileNotFoundError:
                                break
                            if fields[0] == 'Z':
                                break
                            assert backend['process_start_id'] == 'linux-starttime-' + fields[19]
                            time.sleep(0.05)
                        else:
                            raise RuntimeError('Old backend is still running before crash recovery')
                    recovery = {'endpoint_exists_before': (root / 'runtime/endpoint.json').exists()}
                    case['crash_recovery'] = recovery
                    # Keep the same root, endpoint bytes and public port; do not repair fixture state.
                    restarted = run([cli, '--json', 'status'], env)
                    recovery['ordinary_status_exit'] = restarted.returncode
                    status = helper_result(restarted)
                    recovery['ordinary_status_errors'] = status.get('errors')
                    if restarted.returncode:
                        raise RuntimeError('Ordinary CLI cannot recover after the verified host exit')
                    assert status['command'] == 'status' and status['status'] == 'ok' and status['errors'] == []
                    code, recovered = request(port, '/api/health', headers={'X-Respire-Health': 'runtime-v1'})
                    assert code == 200 and recovered['server'] == 'respire' and recovered['v'] == 1
                    assert recovered['instance_id'] != backend['instance_id']
                    assert (recovered['pid'], recovered['process_start_id']) != (backend['pid'], backend['process_start_id'])
                    assert recovered['runtime_version'] == args.runtime_version
                    assert Path(recovered['installation_root']).resolve(strict=True) == root
                    assert recovered['image_sha256'] == selection['sha256']
                    for key in ['installation_id', 'account_id', 'data_dir']:
                        assert recovered[key] == backend[key], key
                    keys = ['pid', 'installation_id', 'instance_id', 'process_start_id', 'image_path', 'image_sha256',
                            'runtime_version', 'account_id', 'generation', 'installation_root', 'data_dir']
                    identity = {key: recovered[key] for key in keys}
                    recovery['new_actor_identity'] = identity
                    reused = run([executable, 'start'], env)
                    reused_result = helper_result(reused)
                    recovery['client2_exit'] = reused.returncode
                    recovery['legacy_rpc_ok'] = reused_result.get('diagnostic_rpc', {}).get('ok')
                    recovery['legacy_rpc_code'] = reused_result.get('diagnostic_rpc', {}).get('code')
                    if reused.returncode or recovery['legacy_rpc_ok'] is not True:
                        raise RuntimeError('Original Client2 cannot reuse the recovered Runtime')
                    code, current = request(port, '/api/health', headers={'X-Respire-Health': 'runtime-v1'})
                    assert code == 200 and {key: current[key] for key in keys} == identity
                    recovery['same_new_actor_after_client2'] = True
                    handle = None
                    if os.name == 'nt':
                        handle = kernel.OpenProcess(0x00100000, False, recovered['pid'])
                        assert handle, 'Cannot observe the recovered backend process'
                    try:
                        stopped = run([executable, 'stop'], env)
                        recovery['client2_stop_exit'] = stopped.returncode
                        if stopped.returncode:
                            raise RuntimeError('Original Client2 cannot normally stop the recovered Runtime')
                        if os.name == 'nt':
                            assert kernel.WaitForSingleObject(handle, 15000) == 0, 'Recovered backend survived normal stop'
                        else:
                            deadline = time.monotonic() + (90 if sys.platform == 'darwin' else 15)
                            while time.monotonic() < deadline:
                                if sys.platform == 'linux':
                                    try:
                                        fields = linux_runtime_record(recovered['pid'])
                                    except FileNotFoundError:
                                        break
                                    if fields[0] == 'Z':
                                        break
                                    assert recovered['process_start_id'] == 'linux-starttime-' + fields[19]
                                else:
                                    observed = subprocess.run(['ps', '-p', str(recovered['pid']), '-o', 'stat='],
                                                              capture_output=True, text=True, timeout=5)
                                    assert observed.returncode in [0, 1], observed.stderr
                                    state = observed.stdout.strip()
                                    if not state or state.startswith('Z'):
                                        break
                                time.sleep(0.05)
                            else:
                                raise RuntimeError('Recovered backend survived normal stop')
                        recovery['stopped_os_process'] = True
                    finally:
                        if handle is not None:
                            kernel.CloseHandle(handle)
                    receipt = json.loads((root / 'runtime' / f"stop-{recovered['instance_id']}.json").read_text())
                    assert receipt['schema_version'] == 1 and receipt['protocol_version'] == 1
                    assert isinstance(receipt['operation_id'], str) and receipt['operation_id']
                    for key in ['pid', 'installation_id', 'instance_id', 'process_start_id', 'image_path',
                                'image_sha256', 'runtime_version', 'account_id', 'generation']:
                        assert receipt[key] == recovered[key], key
                    assert receipt['state'] == 'drained' and receipt['unfinished'] == []
                    with socket.socket() as connection:
                        connection.settimeout(5)
                        assert connection.connect_ex(('127.0.0.1', port)) == errno.ECONNREFUSED
                    recovery['normal_stop_receipt_verified'] = True
                    recovery['listener_closed_after_stop'] = True
            elif mode == 'desktop-owned':
                assert verify_desktop_runtime(desktop_action('status', env), root, image, port) == identity
                desktop_action('stop', env)
                receipt = json.loads((root / 'runtime' / f"stop-{identity['instance_id']}.json").read_text())
                assert receipt['schema_version'] == 1 and receipt['protocol_version'] == 1
                assert isinstance(receipt['operation_id'], str) and receipt['operation_id']
                assert Path(receipt['image_path']).resolve(strict=True) == image
                for key, value in identity.items():
                    assert receipt[key] == value, key
                assert receipt['state'] == 'drained' and receipt['unfinished'] == []
                try:
                    stopped_process = linux_runtime_record(identity['pid'])
                except FileNotFoundError:
                    stopped_process = None
                assert (stopped_process is None or stopped_process[0] == 'Z'
                        or identity['process_start_id'] != 'linux-starttime-' + stopped_process[19])
                with socket.socket() as connection:
                    connection.settimeout(5)
                    assert connection.connect_ex(('127.0.0.1', port)) == errno.ECONNREFUSED
                case['desktop_headless'].update(stop=True, identity_bound_drained_receipt=True,
                                                stopped_os_process=True, listener_closed=True)
            else:
                stopped = run([executable, 'stop'], env)
                case['client2_stop_exit'] = stopped.returncode
                if stopped.returncode:
                    case['errors']['stop_error'] = helper_result(stopped)
                    raise RuntimeError('Client2 cannot stop its visible service')
            case['passed'] = True
        except Exception as error:
            case['failure'] = str(error)
        finally:
            cleanup_command = ([desktop, '--headless', 'stop'] if mode == 'desktop-owned' else
                               [executable, 'stop'] if mode == 'client2-owned' else
                               [cli, '--json', 'runtime', 'stop'])
            stopped = run(cleanup_command, env)
            case['cleanup_exit'] = stopped.returncode
            if stopped.returncode:
                case['passed'] = False
                case['cleanup_error'] = (stopped.stdout + stopped.stderr)[:2000]
            if not case['passed']: annotate_failure(case)
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))
    return 0 if all(case['passed'] for case in report['cases']) else 1

if __name__ == '__main__':
    raise SystemExit(main())
