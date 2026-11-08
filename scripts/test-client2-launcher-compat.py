#!/usr/bin/env python3
"""Real unchanged Client2 v0.2.56 host calls; account-free temporary installations.

Requires official CLI/Runtime bytes and an unmodified checkout of the pinned
Client2 source. This is not GUI, account, model-inference or G1 acceptance.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import urllib.error
import urllib.request

CLIENT2_SHA = '57bc070826949994c3f7ce9a64277160704bdfe5'

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

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cli', type=Path, required=True)
    parser.add_argument('--runtime-archive', type=Path, required=True)
    parser.add_argument('--runtime-version', required=True)
    parser.add_argument('--client2-source', type=Path, required=True)
    parser.add_argument('--go', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--go-mod-cache', type=Path)
    parser.add_argument('--offline', action='store_true')
    args = parser.parse_args()
    cli, archive, source, go = (p.resolve(strict=True) for p in
                                [args.cli, args.runtime_archive, args.client2_source, args.go])
    def git(*argv):
        return subprocess.check_output(['git', '-C', str(source), *argv], text=True).strip()
    if git('rev-parse', 'HEAD') != CLIENT2_SHA or git('status', '--porcelain'):
        raise RuntimeError('Require unchanged Client2 v0.2.56 source')
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
                         'runtime_version': args.runtime_version},
              'excluded': ['desktop GUI', 'accounts and credentials', 'model inference',
                           'managed services', 'cross-platform execution']}
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
    def request(port, path, body=None, headers=None):
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
    for mode in ['client2-owned', 'external-cli-cold-start', 'reuse-cli-started']:
        root = base / mode; root.mkdir(); home = root / 'home'; home.mkdir()
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0)); port = listener.getsockname()[1]
        env = {k: os.environ[k] for k in ['PATH', 'SystemRoot', 'WINDIR', 'TEMP', 'TMP', 'COMSPEC', 'PATHEXT'] if k in os.environ}
        env.update(HOME=str(home), USERPROFILE=str(home), RSRS_DATA_DIR=str(root), RSRS_BIN_DIR=str(root/'bin'),
                   RSRS_RPC_PORT=str(port), RSRS_CORE_TEST_MODE='1', RSRS_NO_AUTOSYNC='1', RSRS_UPDATE_CHECK='0', RSRS_LANG='en')
        for key, name in [('XDG_CONFIG_HOME','config'),('XDG_DATA_HOME','share'),('XDG_CACHE_HOME','cache'),
                          ('XDG_STATE_HOME','state'),('XDG_RUNTIME_DIR','run'),('APPDATA','appdata'),('LOCALAPPDATA','local')]:
            path = root / name; path.mkdir(); env[key] = str(path)
        case = {'name': mode, 'passed': False}; report['cases'].append(case)
        try:
            installed = run([cli, '--json', 'runtime', 'install', '--file', archive, '--version', args.runtime_version], env)
            if installed.returncode: raise RuntimeError('Official Runtime installation failed: '+installed.stderr)
            selection = json.loads((root/'runtime.json').read_text())
            (root/'bin').mkdir(exist_ok=True)
            shutil.copy2(cli, root/'bin'/('rsrs.exe' if os.name=='nt' else 'rsrs'))
            if mode == 'client2-owned':
                destination = root/'client2/runtime'/args.runtime_version
                shutil.copytree(root/'runtime'/args.runtime_version, destination)
                (root/'client2/runtime.json').write_text(json.dumps({'version':args.runtime_version,'sha256':selection['sha256']}))
            if mode == 'reuse-cli-started':
                started = run([cli, '--json', 'runtime', 'start'], env)
                if started.returncode: raise RuntimeError('CLI startup failed: '+started.stderr)
            result = run([executable, 'start'], env)
            payload = helper_result(result)
            case['client2_exit'] = result.returncode
            case['errors'] = {k:v for k,v in payload.items() if k.endswith('_error')}
            case['legacy_rpc_ok'] = payload.get('diagnostic_rpc',{}).get('ok')
            case['legacy_rpc_code'] = payload.get('diagnostic_rpc',{}).get('code')
            if result.returncode or case['legacy_rpc_ok'] is not True:
                raise RuntimeError('Unmodified Client2 startup/business calls failed')
            case['boundaries'] = boundaries(port)
            reused = run([cli, '--json', 'status'], dict(env, RSRS_NO_AUTOSTART='1'))
            case['cli_reuse_exit'] = reused.returncode
            if reused.returncode: raise RuntimeError('CLI cannot reuse Client2-compatible service')
            stopped = run([executable, 'stop'], env)
            case['client2_stop_exit'] = stopped.returncode
            if stopped.returncode:
                case['errors']['stop_error'] = helper_result(stopped)
                raise RuntimeError('Client2 cannot stop its visible service')
            case['passed'] = True
        except Exception as error:
            case['failure'] = str(error)
        finally:
            stopped = run([executable, 'stop'] if mode=='client2-owned' else [cli,'--json','runtime','stop'], env)
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
