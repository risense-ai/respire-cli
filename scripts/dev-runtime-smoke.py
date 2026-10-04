#!/usr/bin/env python3
"""Exact-artifact runtime/dashboard checks on an ephemeral GitHub-hosted Linux runner.

Uses a fresh owned HOME, models and development account. Reports never contain
credentials, command arguments, plaintext responses or raw subprocess logs.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading


REQUIRED = json.loads(Path(__file__).with_name('dev-runtime-required.json').read_text(encoding='utf-8'))['required_cases']
DEV = 'https://dev.rsrs.rs'
DASH = 'https://dash.rsrs.rs'


class Failure(Exception):
    pass


def require(condition, code):
    if not condition:
        raise Failure(code)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


class Smoke:
    def __init__(self, args):
        self.args = args
        self.root = args.root.resolve()
        self.env = None
        self.child = None
        self.token = None
        self.created = False
        self.attempted = False
        self.cloud_clean = True
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        self.user = 'ci-runtime-' + os.environ.get('GITHUB_RUN_ID', '') + '-' + secrets.token_hex(5)
        self.password = '-' + secrets.token_urlsafe(32)
        self.report = {'source_sha': args.source_sha, 'workflow_sha': os.environ.get('GITHUB_SHA'),
                       'version': args.version, 'binary_sha256': args.binary_sha256,
                       'status': 'failed', 'passed': False, 'cases': {}, 'required_cases': REQUIRED,
                       'missing_cases': REQUIRED[:], 'cloud_cleanup': {'passed': False, 'remaining_users': []}}

    def passed(self, name, **evidence):
        require(name in REQUIRED, 'unknown_runtime_case')
        self.report['cases'][name] = {'passed': True, **evidence}

    def direct(self, args, timeout=90, stdin=None, expected=0):
        try:
            result = subprocess.run([str(self.args.binary), '--direct', '--json', *args],
                                    env=self.env, cwd=self.root, input=stdin,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    text=True, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired):
            raise Failure('owned_cli_execution_failed') from None
        require(result.returncode == expected, 'owned_cli_exit_mismatch')
        try:
            value = json.loads(result.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            raise Failure('owned_cli_envelope_invalid') from None
        require(isinstance(value, dict) and all(k in value for k in
                ('command', 'status', 'summary', 'items', 'actions', 'errors', 'details')),
                'owned_cli_envelope_incomplete')
        require(value['status'] in ('ok', 'skip') if expected == 0 else value['status'] == 'fail',
                'owned_cli_status_mismatch')
        return value

    def http(self, base, method, path, body=None, token=None, headers=None, raw=False):
        fields = {'Content-Type': 'application/json', **(headers or {})}
        if token is not None:
            fields['Authorization'] = 'Bearer ' + token
        req = urllib.request.Request(base + path, None if body is None else json.dumps(body).encode(),
                                     fields, method=method)
        try:
            response = self.opener.open(req, timeout=90)
        except urllib.error.HTTPError as error:
            response = error
        except (OSError, urllib.error.URLError):
            raise Failure('owned_http_transport_failed') from None
        with response:
            status, response_headers = response.code, response.headers
            data = response.read(8 * 1024 * 1024 + 1)
        require(len(data) <= 8 * 1024 * 1024, 'owned_http_response_too_large')
        if raw:
            return status, data, response_headers
        try:
            return status, json.loads(data), response_headers
        except (ValueError, UnicodeError):
            raise Failure('owned_http_response_not_json') from None

    def rpc(self, args, expected=0):
        code, reply, _ = self.http(self.url, 'POST', '/api/rpc',
                                  {'v': 1, 'id': secrets.token_hex(8), 'method': 'cli.exec',
                                   'args': ['--json', *args]}, self.token)
        require(code == 200 and isinstance(reply, dict) and reply.get('ok') is (expected == 0),
                'runtime_rpc_transport_failed')
        envelope = reply.get('envelope', {})
        require(reply.get('exit') == expected and envelope.get('status') in
                (('ok', 'skip') if expected == 0 else ('fail',)), 'runtime_rpc_command_failed')
        return envelope

    def stop(self):
        if self.child is None:
            return
        if self.child.poll() is None:
            code, reply, _ = self.http(self.url, 'POST', '/api/runtime/stop', {}, self.token)
            require(code == 200 and reply.get('ok') is True, 'owned_runtime_stop_rejected')
            try:
                self.child.wait(timeout=20)
            except subprocess.TimeoutExpired:
                raise Failure('owned_runtime_stop_timeout') from None
        require(self.child.returncode == 0, 'owned_runtime_stop_exit_failed')
        self.child = None

    def start(self):
        require(self.child is None, 'runtime_already_owned')
        self.child = subprocess.Popen([str(self.args.binary), '--runtime-internal', '--port', str(self.port),
                                       '--host', '127.0.0.1'], env=self.env, cwd=self.root,
                                      stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            require(self.child.poll() is None, 'owned_runtime_exited_before_ready')
            token_path = self.root / 'runtime' / 'token'
            require(not token_path.exists(), 'loopback_runtime_created_token')
            if (self.root / 'runtime' / 'endpoint.json').is_file():
                try:
                    code, health, _ = self.http(self.url, 'GET', '/api/health')
                except Failure:
                    time.sleep(0.1)
                    continue
                if code == 200:
                    require(health.get('v') == 1 and health.get('bin') == self.args.version
                            and health.get('pid') == self.child.pid
                            and Path(health.get('exe', '')).resolve() == self.args.binary
                            and Path(health.get('data_dir', '')).resolve() == self.library,
                            'owned_runtime_identity_mismatch')
                    return
            time.sleep(0.1)
        raise Failure('owned_runtime_ready_timeout')

    def setup(self):
        temp = Path(os.environ.get('RUNNER_TEMP', '')).resolve()
        require(os.environ.get('GITHUB_ACTIONS') == 'true'
                and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'
                and platform.system() == 'Linux', 'ephemeral_github_linux_runner_required')
        require(self.root != temp and self.root.is_relative_to(temp) and not self.root.exists(),
                'fresh_owned_runner_temp_required')
        require(re.fullmatch('[0-9a-f]{40}', self.args.source_sha)
                and re.fullmatch('[0-9a-f]{64}', self.args.binary_sha256)
                and hashlib.sha256(self.args.binary.read_bytes()).hexdigest() == self.args.binary_sha256,
                'exact_binary_identity_mismatch')
        self.root.mkdir(mode=0o700)
        self.created = True
        self.library = self.root / 'library'
        for name in ('home', 'library', 'config', 'data', 'cache', 'tmp', 'runtime', 'bin', 'models'):
            (self.root / name).mkdir(mode=0o700)
        self.env = {k: v for k, v in os.environ.items()
                    if not k.startswith(('ONEMEMORY_', 'RESPIRE_', 'XDG_', 'DS_', 'JEV_', 'GNOME_'))
                    and not k.endswith(('_TOKEN', '_API_KEY')) and 'TEST_MODE' not in k
                    and k not in ('HOME', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA', 'DBUS_SESSION_BUS_ADDRESS')}
        self.env.update(HOME=str(self.root / 'home'), USERPROFILE=str(self.root / 'home'),
                        XDG_CONFIG_HOME=str(self.root / 'config'), XDG_DATA_HOME=str(self.root / 'data'),
                        XDG_CACHE_HOME=str(self.root / 'cache'), XDG_RUNTIME_DIR=str(self.root / 'runtime'),
                        TMPDIR=str(self.root / 'tmp'), ONEMEMORY_DATA_DIR=str(self.root),
                        ONEMEMORY_BIN_DIR=str(self.root / 'bin'), ONEMEMORY_ENGINE='cpu',
                        ONEMEMORY_LANG='en', ONEMEMORY_NO_AUTOSYNC='1', ONEMEMORY_UPDATE_CHECK='0',
                        ONEMEMORY_MODEL_DIR=str(self.root / 'models/bge-base-zh-v1.5'),
                        ONEMEMORY_RERANKER_DIR=str(self.root / 'models/bge-reranker-base'))
        for key in ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy'):
            self.env.pop(key, None)
        with socket.socket() as port:
            port.bind(('127.0.0.1', 0))
            self.port = port.getsockname()[1]
        self.url = 'http://127.0.0.1:' + str(self.port)
        self.env['ONEMEMORY_RPC_PORT'] = str(self.port)
        value = self.direct(['-v'])
        require(value.get('summary', {}).get('version') == self.args.version, 'exact_version_mismatch')
        self.passed('artifact_identity_verified')

    def dashboard(self):
        endpoint = self.root / 'runtime' / 'endpoint.json'
        require(not endpoint.exists(), 'runtime_existed_before_dashboard')
        result = self.direct(['web', '--no-open'])
        require(result['summary'] == {'url': DASH, 'opened': False} and not endpoint.exists(),
                'dashboard_started_runtime_or_wrong_url')
        self.passed('dashboard_url_without_runtime')
        browser = self.root / 'bin' / 'xdg-open'
        capture = self.root / 'browser-url.txt'
        browser.write_text('#!' + sys.executable + '\nimport pathlib,sys\n'
                           + 'pathlib.Path(' + repr(str(capture)) + ').write_text(sys.argv[1],encoding="utf-8")\n', encoding='utf-8')
        browser.chmod(0o700)
        self.env['PATH'] = str(browser.parent) + os.pathsep + self.env.get('PATH', '')
        opened = self.direct(['web'])
        deadline = time.monotonic() + 5
        while not capture.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        require(opened['summary'] == {'url': DASH, 'opened': True}
                and capture.is_file() and capture.read_text(encoding='utf-8') == DASH and not endpoint.exists(),
                'dashboard_browser_launch_failed')
        self.passed('dashboard_browser_launch_verified', method='actual_cli_with_owned_os_browser_handler')
        for flag in ('--status', '--stop', '--internal', '--port', '--host'):
            result = subprocess.run([str(self.args.binary), 'web', flag], env=self.env, cwd=self.root,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
            require(result.returncode != 0 and not endpoint.exists(), 'legacy_web_flag_was_accepted')
        self.passed('dashboard_legacy_flags_rejected')
        for host in ('0.0.0.0', '192.0.2.1', 'example.invalid'):
            self.direct(['--runtime-internal', '--host', host, '--port', str(self.port)], expected=1)
            with socket.socket() as check:
                check.settimeout(1)
                require(check.connect_ex(('127.0.0.1', self.port)) != 0,
                        'nonloopback_runtime_left_listener')
            require(not endpoint.exists() and not (self.root / 'runtime/token').exists(),
                    'nonloopback_runtime_created_endpoint_or_token')
        self.passed('runtime_nonloopback_rejected')
        client_home = self.root / 'client-only-home'
        old = client_home / '.onememory'
        old.mkdir(parents=True, mode=0o700)
        marker = old / 'client.json'
        marker.write_text('{"addr":"https://dev.rsrs.rs"}\n', encoding='utf-8')
        before = {str(path.relative_to(client_home)): hashlib.sha256(path.read_bytes()).hexdigest()
                  for path in client_home.rglob('*') if path.is_file()}
        client_env = dict(self.env, HOME=str(client_home), USERPROFILE=str(client_home),
                          ONEMEMORY_CLIENT_ONLY='1')
        client_env.pop('ONEMEMORY_DATA_DIR', None)
        client_env.pop('RESPIRE_DEFAULT_DATA_DIR', None)
        result = subprocess.run([str(self.args.binary), '--client-only', '--json', 'status'],
                                env=client_env, cwd=self.root, capture_output=True, timeout=25)
        after = {str(path.relative_to(client_home)): hashlib.sha256(path.read_bytes()).hexdigest()
                 for path in client_home.rglob('*') if path.is_file()}
        require(result.returncode != 0 and before == after and not (client_home / '.rsrs').exists()
                and not endpoint.exists(), 'client_only_migrated_or_created_profile')
        self.passed('client_only_no_profile_writes')

    def account(self):
        expected = os.environ.get('RESPIRE_DEV_SERVER_SHA', '')
        require(os.environ.get('RESPIRE_DEV_SERVER_ADDR') == DEV and re.fullmatch('[0-9a-f]{40}', expected),
                'exact_development_server_required')
        code, ready, headers = self.http(DEV, 'GET', '/ready')
        require(code == 200 and headers.get('X-Respire-Server-SHA', '') == expected,
                'development_server_revision_mismatch')
        self.report['server_sha'] = expected
        self.direct(['config', '--data-dir', str(self.library), '--addr', DEV, '--autosync', 'false', '--cure-auto', 'false'])
        config = self.direct(['config'])['summary']
        require(Path(config.get('data_dir', '')).resolve() == self.library and config.get('addr') == DEV,
                'data_dir_configuration_failed')
        self.passed('data_dir_persisted')
        self.direct(['model', 'install-bge'], timeout=1200)
        probe = self.direct(['model', 'probe', '--model', 'legacy'], timeout=180)['summary']
        require(probe.get('ready') is True and probe.get('dimensions') == 768
                and str(probe.get('selected', '')).lower() == 'cpu', 'real_bge_cpu_probe_failed')
        self.attempted = True
        registered = self.direct(['register', '--user', self.user, '--pass=' + self.password, '--addr', DEV])
        require(registered['summary'].get('user') == self.user, 'owned_account_registration_failed')
        self.start()

    def transport(self):
        self.passed('hidden_runtime_health_identity')
        status = self.direct(['--runtime-internal', '--status'])['summary']
        require(status.get('state') == 'up' and status.get('pid') == self.child.pid, 'hidden_status_identity_failed')
        self.passed('hidden_runtime_status_up')
        for token, name in ((None, 'runtime_loopback_without_token'), ('ci-invalid-token', 'runtime_loopback_ignores_token')):
            code, value, _ = self.http(self.url, 'GET', '/api/health', token=token)
            require(code == 200 and value.get('v') == 1 and value.get('bin') == self.args.version
                    and value.get('pid') == self.child.pid
                    and Path(value.get('exe', '')).resolve() == self.args.binary
                    and Path(value.get('data_dir', '')).resolve() == self.library
                    and not (self.root / 'runtime' / 'token').exists(), 'runtime_loopback_health_identity_failed')
            self.passed(name)
        code, value, _ = self.http(self.url, 'POST', '/api/rpc', {}, self.token, {'Origin': 'https://example.invalid'})
        require(code == 403 and value.get('error') == 'forbidden origin', 'runtime_foreign_origin_not_rejected')
        self.passed('runtime_origin_rejected')
        code, value, _ = self.http(self.url, 'POST', '/api/rpc', {'v': 999, 'id': 'bad-version', 'method': 'runtime.status', 'args': []}, self.token)
        require(code == 200 and value.get('ok') is False and value.get('code') == 'protocol_version_mismatch', 'rpc_version_not_rejected')
        self.passed('runtime_rpc_version_rejected')
        config = self.rpc(['config'])['summary']
        require(Path(config.get('data_dir', '')).resolve() == self.library and config.get('addr') == DEV, 'rpc_config_mismatch')
        self.passed('runtime_rpc_config_verified')
        require(self.rpc(['status'])['summary'].get('unlocked') is True, 'runtime_not_unlocked')
        self.passed('runtime_rpc_status_unlocked')
        for method, ident, name in (('initialize', 1, 'runtime_mcp_initialized'), ('tools/list', 2, 'runtime_mcp_tools_list')):
            body = {'jsonrpc': '2.0', 'id': ident, 'method': method}
            if method == 'initialize':
                body['params'] = {'protocolVersion': '2025-03-26', 'capabilities': {}, 'clientInfo': {'name': 'runtime-ci', 'version': '1'}}
            code, value, _ = self.http(self.url, 'POST', '/mcp', body, self.token)
            require(code == 200 and value.get('id') == ident and 'error' not in value, 'mcp_response_failed')
            if method == 'initialize':
                require(value.get('result', {}).get('protocolVersion') == '2025-03-26', 'mcp_protocol_mismatch')
            else:
                tools = value.get('result', {}).get('tools', [])
                require(isinstance(tools, list) and any(tool.get('name') == 'memory_status' for tool in tools), 'mcp_tools_missing')
            self.passed(name)
        for path in ('/', '/index.html', '/favicon.ico', '/fonts/example.ttf', '/api/invoke', '/api/task?id=old'):
            code, value, _ = self.http(self.url, 'POST' if path == '/api/invoke' else 'GET', path,
                                      {} if path == '/api/invoke' else None, self.token)
            require(code == 404 and value.get('error') == 'unknown runtime endpoint', 'removed_ui_route_still_served')
        self.passed('removed_ui_routes_not_served', routes=6)

    def settings(self):
        for mode in ('verbose', 'concise'):
            self.rpc(['agent-config', '--set', 'diary_mode=' + mode])
            require(self.rpc(['agent-config'])['summary'].get('diary_mode') == mode, 'diary_mode_not_persisted')
        self.passed('diary_mode_persisted')
        value = self.rpc(['remember', 'Runtime fixture persisted memory.', '--title', 'Runtime fixture', '--importance', 'important', '--force'])
        memory_id = value['summary'].get('id')
        require(isinstance(memory_id, str) and memory_id, 'owned_memory_not_created')
        self.rpc(['agent-config', '--set', 'readonly=true'])
        rejected = self.rpc(['remember', 'Readonly write must fail.', '--importance', 'important', '--force'], expected=1)
        require('read-only' in ' '.join(rejected.get('errors', [])), 'readonly_write_guard_missing')
        require(self.rpc(['show', memory_id])['details'].get('entry', {}).get('id') == memory_id, 'readonly_read_failed')
        self.rpc(['agent-config', '--set', 'readonly=false'])
        self.rpc(['agent-config', '--set', 'memory_off=true'])
        rejected = self.rpc(['show', memory_id], expected=1)
        require('temporarily off' in ' '.join(rejected.get('errors', [])), 'off_read_guard_missing')
        self.rpc(['agent-config', '--set', 'memory_off=false'])
        normal = self.rpc(['agent-config'])['summary']
        require(normal.get('readonly') is False and normal.get('memory_off') is False, 'normal_mode_not_restored')
        require(self.rpc(['show', memory_id])['details']['entry']['content'] == 'Runtime fixture persisted memory.', 'normal_read_not_restored')
        self.passed('workspace_three_states_persisted')
        self.stop()
        self.start()
        require(self.rpc(['status'])['summary'].get('unlocked') is True
                and self.rpc(['show', memory_id])['details']['entry']['content'] == 'Runtime fixture persisted memory.',
                'stored_session_not_resumed')
        self.passed('resume_session_real', method='fresh_runtime_reuses_owned_session_and_keyring_no_password_input')
        self.stop()
        install = self.direct(['model', 'install-rerank'], timeout=1200)['summary']
        folder = Path(install.get('dir', '')).resolve()
        require(folder == self.root / 'models/bge-reranker-base'
                and (folder / 'onnx/model_quantized.onnx').stat().st_size > 1024 * 1024
                and (folder / 'tokenizer.json').is_file(), 'owned_rerank_model_not_real')
        agent_file = self.root / 'home/.codex/AGENTS.md'
        agent_file.parent.mkdir()
        original = '# Disposable runtime fixture\nKeep this text.\n'
        agent_file.write_text(original, encoding='utf-8')
        self.direct(['inject', '--id', 'codex'])
        installed = agent_file.read_text(encoding='utf-8')
        require(installed != original and original.strip() in installed,
                'owned_agent_injection_not_applied')
        # Keep doctor strict: a fresh supported agent must be actually injected.
        result = subprocess.run([str(self.args.binary), '--direct', '--json', 'doctor'], env=self.env,
                                cwd=self.root, capture_output=True, text=True, timeout=180)
        self.report['doctor'] = {'exit': result.returncode, 'items': []}
        try:
            diagnostic = json.loads(result.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            diagnostic = None
        if isinstance(diagnostic, dict) and isinstance(diagnostic.get('items'), list):
            names = {'store', 'data dir', 'mcp bin', 'mcp http', 'session', 'embedder',
                     'reranker', 'lock', 'remote', 'inject', 'memory status',
                     'tidy counter', 'CLI version'}
            statuses = {'ok', 'warn', 'fail', 'skip', 'pending'}
            self.report['doctor']['items'] = [
                {'name': item['name'], 'status': item['status']}
                for item in diagnostic['items']
                if isinstance(item, dict) and isinstance(item.get('name'), str)
                and item['name'] in names and isinstance(item.get('status'), str)
                and item['status'] in statuses
            ]
        require(result.returncode in (0, 2), 'rerank_doctor_execution_failed')
        require(isinstance(diagnostic, dict) and isinstance(diagnostic.get('items'), list),
                'doctor_envelope_invalid')
        require(any(item.get('name') == 'inject' and item.get('status') == 'ok'
                    for item in diagnostic.get('items', [])), 'owned_agent_doctor_not_fresh')
        require(any(item.get('name') == 'reranker' and item.get('status') == 'ok'
                    for item in diagnostic.get('items', [])), 'rerank_doctor_status_not_ready')
        self.passed('rerank_status_real', model_sha256=hashlib.sha256((folder / 'onnx/model_quantized.onnx').read_bytes()).hexdigest())
        self.direct(['classify-config', '--set', '--backend', 'jev'])
        require(self.direct(['classify-config'])['summary'].get('backend') == 'jev', 'backend_not_persisted')
        self.passed('classify_config_persisted')
        observed = []
        class Trap(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_POST(self):
                observed.append(True)
                self.send_error(503)
            do_GET = do_POST
        trap = ThreadingHTTPServer(('127.0.0.1', 0), Trap)
        thread = threading.Thread(target=trap.serve_forever, daemon=True)
        thread.start()
        try:
            base = 'http://127.0.0.1:' + str(trap.server_port) + '/v1'
            value = self.direct(['classify-config', '--set', '--backend', 'ds', '--api-base', base,
                                 '--model', 'ci-unused-model', '--key-stdin'], stdin='ci-unused-runtime-key\n')['summary']
            readback = self.direct(['classify-config'])['summary']
            require(value.get('has_key') is True and readback.get('backend') == 'ds'
                    and readback.get('api_base') == base and readback.get('model') == 'ci-unused-model'
                    and not observed, 'provider_key_config_or_network_guard_failed')
            self.passed('ds_key_saved_without_network', provider_requests=0)
        finally:
            trap.shutdown()
            trap.server_close()
            thread.join(timeout=5)
        self.start()
        self.stop()
        require(self.child is None, 'runtime_not_stopped')
        self.passed('hidden_runtime_stop_clean')

    def cleanup(self):
        try:
            self.stop()
        except Exception:
            self.cloud_clean = False
        if self.child is not None and self.child.poll() is None:
            self.child.terminate()
            try:
                self.child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.child.kill()
                self.child.wait(timeout=5)
        if self.attempted:
            try:
                session = json.loads((self.library / 'session.json').read_text(encoding='utf-8'))
                require(session.get('user') == self.user and session.get('addr') == DEV, 'cleanup_identity_mismatch')
                token = session['token']
                code, result, _ = self.http(DEV, 'POST', '/api/self/purge', {'confirm': self.user}, token)
                require(code == 200 and result.get('purged') is True, 'cloud_purge_failed')
                code, _, _ = self.http(DEV, 'GET', '/api/self', token=token)
                require(code == 401, 'old_account_token_not_revoked')
            except Exception:
                self.cloud_clean = False
        self.report['cloud_cleanup'] = {'passed': self.cloud_clean,
                                        'remaining_users': [] if self.cloud_clean else [self.user] if self.attempted else []}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--binary-sha256', required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--source-sha', required=True)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    args.binary = args.binary.resolve()
    destination = args.report.resolve() if args.report else args.root.resolve() / 'runtime-coverage.json'
    temp = Path(os.environ.get('RUNNER_TEMP', '')).resolve()
    require(destination != temp and destination.is_relative_to(temp) and not destination.exists(),
            'report_path_must_be_fresh_runner_temp_file')
    smoke = Smoke(args)
    try:
        smoke.setup()
        smoke.dashboard()
        smoke.account()
        smoke.transport()
        smoke.settings()
    except Exception as error:
        smoke.report['failure_code'] = str(error) if isinstance(error, Failure) else type(error).__name__
    finally:
        smoke.cleanup()
    smoke.report['missing_cases'] = [name for name in REQUIRED if smoke.report['cases'].get(name, {}).get('passed') is not True]
    smoke.report['passed'] = not smoke.report['missing_cases'] and not smoke.report.get('failure_code') and smoke.cloud_clean
    smoke.report['status'] = 'passed' if smoke.report['passed'] else 'failed'
    if smoke.created:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(smoke.report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'passed': smoke.report['passed'], 'failure_code': smoke.report.get('failure_code'),
                      'missing_cases': smoke.report['missing_cases'], 'cloud_cleanup': smoke.report['cloud_cleanup']}))
    return 0 if smoke.report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
