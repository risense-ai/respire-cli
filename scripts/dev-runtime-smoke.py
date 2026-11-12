#!/usr/bin/env python3
"""Published Runtime/dashboard checks on an ephemeral GitHub-hosted Linux runner.

Uses a fresh owned HOME, models and development account. Reports never contain
credentials, command arguments, plaintext responses or raw subprocess logs.
Legacy mode is explicitly separate from standalone Runtime evidence; neither is G1.
"""
import argparse
import ctypes
import multiprocessing
import signal
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
from native_fixture_process import (install_published_runtime, add_runtime_arguments, runtime_inputs, runtime_report,
                                    verify_runtime_health, scoped_rpc_request, verify_rpc_receipt, RuntimeHealthFailure)


REQUIRED = json.loads(Path(__file__).with_name('dev-runtime-required.json').read_text(encoding='utf-8'))['required_cases']
DEV = 'https://api-dev.rsrs.rs'
DASH = 'https://dash.rsrs.rs'


DIRECT_CASE_IDS = frozenset({'owned_cli', 'nonloopback_unspecified_ipv4',
                             'nonloopback_documentation_ipv4', 'nonloopback_dns'})
CLI_REASONS = frozenset({'invalid_input', 'runtime_error', 'request_outcome_unknown'})


def exit_diagnostic(case_id, expected, result):
    reason = 'unknown'
    try:
        value = json.loads(result.stdout.strip().splitlines()[-1])
        candidate = value.get('summary', {}).get('reason')
        if type(candidate) is str and candidate in CLI_REASONS:
            reason = candidate
    except (ValueError, IndexError, AttributeError, TypeError):
        pass
    return {'case_id': case_id if type(case_id) is str and case_id in DIRECT_CASE_IDS else 'owned_cli',
            'expected_exit': expected if type(expected) is int else None,
            'actual_exit': result.returncode if type(result.returncode) is int else None,
            'structured_reason': reason}


class Failure(Exception):
    pass


def require(condition, code):
    if not condition:
        raise Failure(code)


def private_fixture_bus(env):
    bus = env.get('DBUS_SESSION_BUS_ADDRESS', '')
    if (sys.platform.startswith('linux') and env.get('RSRS_SS_FIXTURE_BUS') == 'private'
            and re.fullmatch(r'unix:(?:path|abstract)=[^,;\s]+(?:,guid=[0-9a-f]{32})?', bus)):
        return bus
    return None


class RuntimeProviderKeys:
    """Exact absent-before-write provider slots on a dedicated wrapper-owned bus.

    Login aliases stay alive for resume_session_real and are cleaned by the
    owning wrapper. Never enumerate/delete host credentials or read secrets.
    """
    def __init__(self, env):
        require(private_fixture_bus(env) is not None
                and private_fixture_bus(env) == private_fixture_bus(os.environ),
                'private_runtime_fixture_bus_required')
        import secretstorage
        from jeepney import DBusAddress, new_method_call
        self.connection = secretstorage.dbus_init()
        self.address = DBusAddress('/org/freedesktop/DBus', 'org.freedesktop.DBus',
                                   'org.freedesktop.DBus')
        self.new_method_call = new_method_call
        self.owner = self.current_owner()
        self.collection = secretstorage.get_collection_by_alias(self.connection, 'default')
        require(not self.collection.is_locked() and not list(self.collection.get_all_items()),
                'runtime_fixture_collection_not_empty_or_locked')
        self.slots = set()

    def current_owner(self):
        return self.connection.send_and_get_reply(self.new_method_call(
            self.address, 'GetNameOwner', 's', ('org.freedesktop.secrets',))).body

    def verify_owner(self):
        require(self.current_owner() == self.owner, 'runtime_fixture_owner_changed')

    @staticmethod
    def attributes(slot):
        return {'service': 'rsrs', 'target': 'default', 'username': slot,
                'application': 'rust-keyring'}

    def items(self, slot):
        self.verify_owner()
        attributes = self.attributes(slot)
        items = list(self.collection.search_items({k: attributes[k]
                     for k in ('service', 'target', 'username')}))
        require(len(items) <= 1, 'runtime_provider_slot_ambiguous')
        for item in items:
            require(all(item.get_attributes().get(k) == v for k, v in attributes.items()),
                    'runtime_provider_slot_attributes_mismatch')
        return items

    def reserve(self, slot):
        require(slot in ('classify:last-backend', 'classify:ds-last-base')
                or re.fullmatch(r'classify:ds(?:-model)?@127\.0\.0\.1:[0-9]{1,5}', slot),
                'runtime_provider_slot_not_owned')
        require(slot not in self.slots and not self.items(slot), 'runtime_provider_slot_exists')
        self.slots.add(slot)

    def cleanup(self):
        passed = True
        for slot in sorted(self.slots):
            try:
                for item in self.items(slot):
                    item.delete()
                require(not self.items(slot), 'runtime_provider_slot_not_removed')
            except Exception:
                passed = False
        return passed


def rejection_children():
    # This is the private subreaper's direct/adopted children, not a PID sweep.
    pid = os.getpid()
    return [int(value) for value in Path(f'/proc/{pid}/task/{pid}/children').read_text().split()]


def preflight_rejection_pidfd():
    require(hasattr(os, 'pidfd_open') and hasattr(signal, 'pidfd_send_signal'),
            'nonloopback_containment_unavailable')
    fd = os.pidfd_open(os.getpid())
    try:
        signal.pidfd_send_signal(fd, 0)
    finally:
        os.close(fd)


def kill_rejection_child(pid):
    # This single-threaded supervisor never reaps between identity verification
    # and signaling. A direct/adopted child's PID cannot be reused until reaped.
    try:
        before = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[19]
        fd = None
        degraded = False
        try:
            try:
                fd = os.pidfd_open(pid)
            except OSError:
                degraded = True
            after = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[19]
            require(before == after and pid in rejection_children(), 'nonloopback_cleanup_identity_failed')
            if fd is None:
                os.kill(pid, signal.SIGKILL)
            else:
                try:
                    signal.pidfd_send_signal(fd, signal.SIGKILL)
                except OSError:
                    # Still our unreaped child, with no intervening waitpid.
                    os.kill(pid, signal.SIGKILL)
                    degraded = True
            return degraded
        finally:
            if fd is not None:
                os.close(fd)
    except (ProcessLookupError, FileNotFoundError):
        return False


def reap_rejection_children(deadline):
    leaked = False
    failed = False
    while True:
        children = rejection_children()
        if not children:
            require(not failed, 'nonloopback_cleanup_failed')
            return leaked
        leaked = True
        for pid in children:
            try:
                failed = kill_rejection_child(pid) is True or failed
            except Exception:
                # One child failure must not strand the other owned children.
                failed = True
        while True:
            try:
                pid, _ = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                break
            except OSError:
                failed = True
                break
            if pid == 0:
                break
        require(time.monotonic() < deadline, 'nonloopback_cleanup_timeout')
        time.sleep(0.01)


def rejection_supervisor(connection, command, env, root, timeout):
    # A dedicated subreaper retains even setsid() descendants after CLI exit.
    # The parent fixture and unrelated children are outside this boundary.
    response = {'error': 'nonloopback_execution_failed'}
    process = None
    def interrupted(signum, frame):
        raise OSError('supervisor interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        require(libc.prctl(36, 1, 0, 0, 0) == 0, 'nonloopback_containment_unavailable')
        preflight_rejection_pidfd()
        process = subprocess.Popen(command, env=env, cwd=root, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            # A fast normal exit may already be a zombie, with no /proc exe.
            if process.poll() is None:
                try:
                    image = Path(f'/proc/{process.pid}/exe').resolve(strict=True)
                except FileNotFoundError:
                    require(process.poll() is not None, 'nonloopback_process_image_mismatch')
                else:
                    require(image == Path(command[0]).resolve(strict=True),
                            'nonloopback_process_image_mismatch')
            stdout, stderr = process.communicate(timeout=timeout)
            response = {'returncode': process.returncode, 'stdout': stdout, 'stderr': stderr}
        except (OSError, subprocess.TimeoutExpired, Failure):
            response = {'error': 'nonloopback_execution_failed'}
    except Exception:
        response = {'error': 'nonloopback_execution_failed'}
    finally:
        # Do not let another parent cancellation interrupt descendant cleanup.
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        try:
            leaked = reap_rejection_children(time.monotonic() + 5)
            if leaked:
                response = {'error': 'nonloopback_descendant_cleanup_required'}
            if process is not None:
                # waitpid above can already have reaped the direct child.
                process.wait(timeout=1)
                process.stdout.close()
                process.stderr.close()
        except Exception:
            response = {'error': 'nonloopback_cleanup_failed'}
        try:
            connection.send(response)
        finally:
            connection.close()


def contained_rejection_run(command, env, root, timeout=90):
    require(sys.platform.startswith('linux'), 'nonloopback_containment_unavailable')
    context = multiprocessing.get_context('fork')
    reader, writer = context.Pipe(duplex=False)
    supervisor = context.Process(target=rejection_supervisor,
                                 args=(writer, command, env, root, timeout))
    started = False
    try:
        supervisor.start()
        started = True
        writer.close()
        cancelled = not reader.poll(timeout + 10)
        if cancelled:
            supervisor.terminate()  # SIGTERM requests its finally cleanup, not SIGKILL.
            require(reader.poll(10), 'nonloopback_cleanup_unconfirmed')
        response = reader.recv()
        supervisor.join(5)
        require(not supervisor.is_alive() and supervisor.exitcode == 0,
                'nonloopback_cleanup_unconfirmed')
        require(not cancelled, 'nonloopback_execution_failed')
        require('error' not in response, response.get('error', 'nonloopback_execution_failed'))
        return subprocess.CompletedProcess([], response['returncode'], response['stdout'], response['stderr'])
    except (EOFError, OSError):
        raise Failure('nonloopback_execution_failed') from None
    finally:
        reader.close()
        writer.close()
        if started and supervisor.is_alive():
            supervisor.terminate()
            supervisor.join(10)
        # Never forcibly kill a still-cleaning subreaper and abandon its children.


def client_only_diagnostic(result, before, after, profile_exists, endpoint_exists):
    # Fixed predicates only: never persist captured output, filenames or hashes.
    return {
        'case_id': 'client_only_no_profile_writes',
        'actual_exit': result.returncode if type(result.returncode) is int else None,
        'failed_checks': [name for name, passed in (
            ('command_rejected', type(result.returncode) is int and result.returncode != 0),
            ('home_files_unchanged', before == after),
            ('profile_absent', not profile_exists),
            ('endpoint_absent', not endpoint_exists),
        ) if not passed],
    }


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
        self.provider_keys = None
        self.provider_clean = True
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        self.user = 'ci-runtime-' + os.environ.get('GITHUB_RUN_ID', '') + '-' + secrets.token_hex(5)
        self.password = '-' + secrets.token_urlsafe(32)
        self.report = {'source_sha': args.source_sha, 'workflow_sha': os.environ.get('GITHUB_SHA'),
                       'version': args.version, 'binary_sha256': args.binary_sha256,
                       'runtime_mode': 'explicit_cli_shim', 'standalone_runtime_evidence': False,
                       'status': 'failed', 'passed': False, 'cases': {}, 'required_cases': REQUIRED,
                       'missing_cases': REQUIRED[:], 'cloud_cleanup': {'passed': False, 'remaining_users': []}}
        self.report.update(runtime_report(args, False))

    def passed(self, name, **evidence):
        require(name in REQUIRED, 'unknown_runtime_case')
        self.report['cases'][name] = {'passed': True, **evidence}

    def direct(self, args, timeout=90, stdin=None, expected=0, case_id='owned_cli'):
        try:
            result = subprocess.run([str(self.args.binary), '--direct', '--json', *args],
                                    env=self.env, cwd=self.root, input=stdin,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    text=True, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired):
            raise Failure('owned_cli_execution_failed') from None
        if result.returncode != expected:
            self.report['failure_diagnostic'] = exit_diagnostic(case_id, expected, result)
            raise Failure('owned_cli_exit_mismatch')
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

    def nonloopback_no_effects(self):
        # Check before and after each individual probe, not only after the pair.
        with socket.socket() as check:
            check.settimeout(1)
            require(check.connect_ex(('127.0.0.1', self.port)) != 0,
                    'nonloopback_runtime_left_listener')
        require(not (self.root / 'runtime/endpoint.json').exists()
                and not (self.root / 'runtime/token').exists(),
                'nonloopback_runtime_created_endpoint_or_token')

    def nonloopback(self, host, case_id):
        cases = {
            '0.0.0.0': ('nonloopback_unspecified_ipv4', 'local runtime cannot bind a non-loopback address'),
            '192.0.2.1': ('nonloopback_documentation_ipv4', 'local runtime cannot bind a non-loopback address'),
            'example.invalid': ('nonloopback_dns', 'local runtime requires a literal loopback IP or localhost'),
        }
        require(host in cases and cases[host][0] == case_id, 'nonloopback_case_invalid')
        self.nonloopback_no_effects()
        if not self.args.runtime_binary:
            # The explicitly selected legacy shim still has its CLI envelope contract.
            self.direct(['--runtime-internal', '--host', host, '--port', str(self.port)],
                        expected=1, case_id=case_id)
            self.nonloopback_no_effects()
            return
        # CLI forwarding discards child stdio. Verify the same installed image's
        # rejection separately via its supported unsupervised serve entry point.
        # No boot token, grant, registration, or ownership state is manufactured.
        launches = (
            ('runtime_host_rejection', [str(self.args.runtime_binary), 'serve',
             '--host', host, '--port', str(self.port)]),
            ('cli_runtime_forwarding', [str(self.args.binary), '--direct', '--json',
             '--runtime-internal', '--host', host, '--port', str(self.port)]),
        )
        for probe_id, command in launches:
            self.nonloopback_no_effects()
            try:
                result = contained_rejection_run(command, self.env, self.root)
            except (OSError, subprocess.TimeoutExpired):
                raise Failure('nonloopback_execution_failed') from None
            finally:
                # The supervisor has already killed/reaped its exact descendants;
                # check filesystem/listener effects even after launch/timeout errors.
                self.nonloopback_no_effects()
            # Only fixed classifications, booleans and lengths may leave this process.
            self.report['failure_diagnostic'] = {
                'case_id': case_id, 'probe_id': probe_id, 'expected_exit': 2,
                'actual_exit': result.returncode if type(result.returncode) is int else None,
            }
            expected_stdout = f'runtime=starting host={host} port={self.port}\n' if probe_id == 'runtime_host_rejection' else ''
            expected_stderr = 'rsrs-runtime: ' + cases[host][1] + '\n' if probe_id == 'runtime_host_rejection' else ''
            stdout_match, stderr_match = result.stdout == expected_stdout, result.stderr == expected_stderr
            self.report['failure_diagnostic'].update(
                stdout_expected_match=stdout_match, stderr_expected_match=stderr_match,
                stdout_utf8_bytes=len(result.stdout.encode('utf-8')), stderr_utf8_bytes=len(result.stderr.encode('utf-8')),
                output_classification='expected_output' if stdout_match and stderr_match else 'output_mismatch')
            require(type(result.returncode) is int and result.returncode == 2,
                    'nonloopback_exit_mismatch')
            if probe_id == 'runtime_host_rejection':
                require(result.stderr == 'rsrs-runtime: ' + cases[host][1] + '\n'
                        and result.stdout == f'runtime=starting host={host} port={self.port}\n',
                        'nonloopback_rejection_reason_mismatch')
            else:
                require(result.stdout == '' and result.stderr == '',
                        'nonloopback_forwarding_output_mismatch')
            self.report.pop('failure_diagnostic', None)

    def http(self, base, method, path, body=None, token=None, headers=None, raw=False):
        fields = {'Content-Type': 'application/json', **(headers or {})}
        if method == 'GET' and path == '/api/health':
            # Request backend identity, not the Client2 compatibility-host view.
            fields['X-Respire-Health'] = 'runtime-v1'
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
        body = {'v': 1, 'id': secrets.token_hex(8), 'method': 'cli.exec', 'args': ['--json', *args]}
        if self.args.runtime_binary:
            code, health, _ = self.http(self.url, 'GET', '/api/health')
            require(code == 200, 'runtime_scope_health_failed')
            verify_runtime_health(self.args, health, self.root, self.library, self.child.pid)
            body = scoped_rpc_request(health, ['--json', *args])
        code, reply, _ = self.http(self.url, 'POST', '/api/rpc',
                                  body, self.token)
        if self.args.runtime_binary:
            verify_rpc_receipt(body, reply)
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
            if self.args.runtime_binary:
                self.direct(['--runtime-internal', '--stop'])
            else:
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
        if self.args.runtime_binary:
            self.direct(['--runtime-internal', '--stop'])
        launch = ([str(self.args.runtime_binary), 'serve'] if self.args.runtime_binary else
                  [str(self.args.binary), '--runtime-internal'])
        self.child = subprocess.Popen([*launch, '--port', str(self.port),
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
                    if self.args.runtime_binary:
                        verify_runtime_health(self.args, health, self.root, self.library, self.child.pid)
                    else:
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
                    and k not in ('HOME', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA', 'DBUS_SESSION_BUS_ADDRESS',
                                  'RSRS_SS_FIXTURE_BUS', 'DBUS_STARTER_ADDRESS', 'DBUS_STARTER_BUS_TYPE',
                                  'DBUS_SESSION_BUS_PID', 'SSH_AUTH_SOCK', 'RSRS_SUPER')}
        bus = private_fixture_bus(os.environ)
        if bus is not None:
            self.env.update(DBUS_SESSION_BUS_ADDRESS=bus, RSRS_SS_FIXTURE_BUS='private')
        self.env.update(HOME=str(self.root / 'home'), USERPROFILE=str(self.root / 'home'),
                        XDG_CONFIG_HOME=str(self.root / 'config'), XDG_DATA_HOME=str(self.root / 'data'),
                        XDG_CACHE_HOME=str(self.root / 'cache'), XDG_RUNTIME_DIR=str(self.root / 'runtime'),
                        TMPDIR=str(self.root / 'tmp'), RSRS_DATA_DIR=str(self.root),
                        RSRS_BIN_DIR=str(self.root / 'bin'), RSRS_ENGINE='cpu',
                        RSRS_RUNTIME_BIN=str(self.args.runtime_binary or self.args.binary.resolve()),
                        RSRS_LANG='en', RSRS_NO_AUTOSYNC='1', RSRS_UPDATE_CHECK='0',
                        RSRS_M3_DIR=str(self.root / 'models/bge-m3'),
                        )
        if self.args.runtime_binary:
            self.env['LC_ALL'] = 'C'
        for key in ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy'):
            self.env.pop(key, None)
        self.provider_keys = RuntimeProviderKeys(self.env)
        with socket.socket() as port:
            port.bind(('127.0.0.1', 0))
            self.port = port.getsockname()[1]
        self.url = 'http://127.0.0.1:' + str(self.port)
        self.env['RSRS_RPC_PORT'] = str(self.port)
        installed = install_published_runtime(self.args.binary, self.env)
        if installed is not None:
            self.args.runtime_binary = installed
            if os.environ.get('RSRS_ARTIFACT_SOURCE') != 'published-assets':
                receipt = json.loads((Path(self.env['RSRS_DATA_DIR']) / 'runtime.json').read_text(encoding='utf-8'))
                self.args.runtime_version, self.args.runtime_sha256 = receipt['version'], receipt['sha256']
                runtime_inputs(self.args, [self.args.binary])
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
        for host, case_id in (('0.0.0.0', 'nonloopback_unspecified_ipv4'),
                              ('192.0.2.1', 'nonloopback_documentation_ipv4'),
                              ('example.invalid', 'nonloopback_dns')):
            self.nonloopback(host, case_id)
        self.passed('runtime_nonloopback_rejected')
        client_home = self.root / 'client-only-home'
        old = client_home / '.onememory'
        old.mkdir(parents=True, mode=0o700)
        marker = old / 'client.json'
        marker.write_text('{"addr":"https://api-dev.rsrs.rs"}\n', encoding='utf-8')
        before = {str(path.relative_to(client_home)): hashlib.sha256(path.read_bytes()).hexdigest()
                  for path in client_home.rglob('*') if path.is_file()}
        client_env = dict(self.env, HOME=str(client_home), USERPROFILE=str(client_home),
                          RSRS_CLIENT_ONLY='1')
        client_env.pop('RSRS_DATA_DIR', None)
        client_env.pop('RSRS_DEFAULT_DATA_DIR', None)
        result = subprocess.run([str(self.args.binary), '--client-only', '--json', 'status'],
                                env=client_env, cwd=self.root, capture_output=True, timeout=25)
        after = {str(path.relative_to(client_home)): hashlib.sha256(path.read_bytes()).hexdigest()
                 for path in client_home.rglob('*') if path.is_file()}
        diagnostic = client_only_diagnostic(result, before, after,
                                            (client_home / '.rsrs').exists(), endpoint.exists())
        if diagnostic['failed_checks']:
            self.report['failure_diagnostic'] = diagnostic
            raise Failure('client_only_migrated_or_created_profile')
        self.passed('client_only_no_profile_writes')

    def account(self):
        expected = os.environ.get('RSRS_DEV_SERVER_SHA', '')
        require(os.environ.get('RSRS_DEV_SERVER_ADDR') == DEV and re.fullmatch('[0-9a-f]{40}', expected),
                'exact_development_server_required')
        code, health, _ = self.http(DEV, 'GET', '/health')
        require(code == 200 and isinstance(health, dict) and health.get('source_revision') == expected,
                'development_server_revision_mismatch')
        self.report['server_sha'] = expected
        self.direct(['config', '--data-dir', str(self.library), '--addr', DEV, '--autosync', 'false', '--cure-auto', 'false'])
        config = self.direct(['config'])['summary']
        require(Path(config.get('data_dir', '')).resolve() == self.library and config.get('addr') == DEV,
                'data_dir_configuration_failed')
        self.passed('data_dir_persisted')
        self.direct(['model', 'install-m3'], timeout=1200)
        probe = self.direct(['model', 'probe', '--model', 'm3'], timeout=180)['summary']
        require(probe.get('ready') is True and probe.get('dimensions') == 1024
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
            if self.args.runtime_binary:
                require(code == 200, 'runtime_loopback_health_status_failed')
                verify_runtime_health(self.args, value, self.root, self.library, self.child.pid)
            else:
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
        if self.args.runtime_binary:
            rejected = self.rpc(['config'], expected=2)
            require(rejected['details'].get('error_type') == 'host_boundary', 'host_config_not_fenced')
            config = self.direct(['config'])['summary']
        else:
            config = self.rpc(['config'])['summary']
        require(Path(config.get('data_dir', '')).resolve() == self.library and config.get('addr') == DEV, 'rpc_config_mismatch')
        self.passed('runtime_rpc_config_verified', host_boundary_rejected=bool(self.args.runtime_binary),
                    config_owner='host_cli' if self.args.runtime_binary else 'legacy_shim')
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

    def agent_config(self, args):
        if not self.args.runtime_binary:
            return self.rpc(['agent-config', *args])
        # This is a host-owned profile change, not a fallback after an RPC failure.
        self.stop()
        value = self.direct(['agent-config', *args])
        self.start()
        return value

    def settings(self):
        for mode in ('verbose', 'concise'):
            self.agent_config(['--set', 'diary_mode=' + mode])
            require(self.agent_config([])['summary'].get('diary_mode') == mode, 'diary_mode_not_persisted')
        self.passed('diary_mode_persisted')
        value = self.rpc(['remember', 'Runtime fixture persisted memory.', '--title', 'Runtime fixture', '--importance', 'important', '--force'])
        memory_id = value['summary'].get('id')
        require(isinstance(memory_id, str) and memory_id, 'owned_memory_not_created')
        self.agent_config(['--set', 'readonly=true'])
        rejected = self.rpc(['remember', 'Readonly write must fail.', '--importance', 'important', '--force'], expected=1)
        require('read-only' in ' '.join(rejected.get('errors', [])), 'readonly_write_guard_missing')
        require(self.rpc(['show', memory_id])['details'].get('entry', {}).get('id') == memory_id, 'readonly_read_failed')
        self.agent_config(['--set', 'readonly=false'])
        self.agent_config(['--set', 'memory_off=true'])
        skipped = self.rpc(['show', memory_id])
        require(skipped.get('summary') == {'mode': 'off', 'skipped': True, 'count': 0}
                and skipped.get('items') == [] and skipped.get('details') == []
                and skipped.get('errors') == [], 'off_read_empty_response_missing')
        self.agent_config(['--set', 'memory_off=false'])
        normal = self.agent_config([])['summary']
        require(normal.get('readonly') is False and normal.get('memory_off') is False, 'normal_mode_not_restored')
        require(self.rpc(['show', memory_id])['details']['entry']['content'] == 'Runtime fixture persisted memory.', 'normal_read_not_restored')
        self.passed('workspace_three_states_persisted')
        self.stop()
        self.start()
        require(self.rpc(['status'])['summary'].get('unlocked') is True
                and self.rpc(['show', memory_id])['details']['entry']['content'] == 'Runtime fixture persisted memory.',
                'stored_session_not_resumed')
        self.passed('resume_session_real', method='fresh_runtime_reuses_owned_session_and_keyring_no_password_input')
        # Remember persists before deriving its index. Exercise recall and wait
        # for the owned worker before stopping it for strict offline diagnosis.
        require(self.rpc(['recall', 'Runtime fixture persisted memory.', '--titles']).get('items'),
                'resumed_pending_source_not_recalled')
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            code, health, _ = self.http(self.url, 'GET', '/api/health', token=self.token)
            require(code == 200, 'owned_index_health_unavailable')
            index = health.get('retrieval_index', {})
            require(index.get('state') != 'failed', 'owned_index_preparation_failed')
            if index.get('state') == 'ready' and not index.get('running') and not index.get('scheduled'):
                break
            time.sleep(.1)
        else:
            raise Failure('owned_index_not_ready_before_offline_doctor')
        self.stop()
        retired = subprocess.run([str(self.args.binary), '--direct', '--json', 'model', 'install-rerank'], env=self.env,
                                 cwd=self.root, capture_output=True, text=True, timeout=30)
        require(retired.returncode == 2, 'retired_reranker_command_was_accepted')
        agent_file = self.root / 'home/.codex/AGENTS.md'
        agent_file.parent.mkdir()
        original = '# Disposable runtime fixture\nKeep this text.\n'
        agent_file.write_text(original, encoding='utf-8')
        self.direct(['inject', '--id', 'codex'])
        installed = agent_file.read_text(encoding='utf-8')
        require(installed != original and original.strip() in installed,
                'owned_agent_injection_not_applied')
        self.direct(['inject', '--id', 'generic'])
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
                     'lock', 'remote', 'inject', 'memory status',
                     'tidy counter', 'CLI version', 'Runtime version', 'model index'}
            statuses = {'ok', 'warn', 'fail', 'skip', 'pending'}
            self.report['doctor']['items'] = [
                {'name': item['name'], 'status': item['status']}
                for item in diagnostic['items']
                if isinstance(item, dict) and isinstance(item.get('name'), str)
                and item['name'] in names and isinstance(item.get('status'), str)
                and item['status'] in statuses
            ]
        require(result.returncode in (0, 2), 'm3_doctor_execution_failed')
        require(isinstance(diagnostic, dict) and isinstance(diagnostic.get('items'), list),
                'doctor_envelope_invalid')
        require(any(item.get('name') == 'inject' and item.get('status') == 'ok'
                    for item in diagnostic.get('items', [])), 'owned_agent_doctor_not_fresh')
        require(not any(item.get('name') == 'reranker' for item in diagnostic.get('items', [])), 'retired_reranker_doctor_entry_present')
        require(any(item.get('name') == 'embedder' and item.get('status') == 'ok' for item in diagnostic.get('items', [])), 'm3_doctor_not_ready')
        self.passed('m3_status_real', retired_command_exit=retired.returncode)
        self.provider_keys.reserve('classify:last-backend')
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
            for slot in ('classify:ds-last-base', f'classify:ds@127.0.0.1:{trap.server_port}',
                         f'classify:ds-model@127.0.0.1:{trap.server_port}'):
                self.provider_keys.reserve(slot)
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
        try:
            if self.child is not None and self.child.poll() is None:
                self.child.terminate()
                try:
                    self.child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.child.kill()
                    self.child.wait(timeout=5)
        except Exception:
            # Preserve teardown failure, but still attempt exact credential and
            # cloud cleanup. The outer wrapper also owns process containment.
            self.cloud_clean = False
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
        if self.provider_keys is not None:
            try:
                self.provider_clean = self.provider_keys.cleanup()
            except Exception:
                self.provider_clean = False
        self.report['provider_credential_cleanup'] = {'passed': self.provider_clean}
        self.report['cloud_cleanup'] = {'passed': self.cloud_clean,
                                        'remaining_users': [] if self.cloud_clean else [self.user] if self.attempted else []}

    def doctor_model_recovery(self):
        """Exercise a real failed download and retry against the exact artifact."""
        require(self.child is None, 'doctor_fixture_requires_stopped_runtime')
        model = Path(self.env['RSRS_M3_DIR'])
        cache = self.root / 'doctor-model-cache'
        self.start()
        candidates = self.rpc(['recall', 'Runtime fixture persisted memory.', '--titles'])['details']
        candidate_ids = [row['id'] for row in candidates]
        require(bool(candidate_ids), 'doctor_baseline_candidates_missing')
        self.stop()
        model.rename(cache)
        database = self.library / 'rsrs.db'

        def asset_digests(directory):
            values = {}
            for name in ('tokenizer.json', 'onnx/model_quantized.onnx'):
                with (directory / name).open('rb') as stream:
                    values[name] = hashlib.file_digest(stream, 'sha256').hexdigest()
            return values

        expected_assets = asset_digests(cache)

        def snapshot():
            with sqlite3.connect(database) as db:
                return (db.execute('SELECT id,user,ciphertext,nonce,dirty,deleted,created_at,updated_at FROM memories ORDER BY id').fetchall(),
                        db.execute('SELECT * FROM sync_outbox ORDER BY seq').fetchall())

        before = snapshot()
        session = (self.library / 'session.json').read_bytes()
        with sqlite3.connect(database) as db:
            db.execute('DELETE FROM core_artifacts')
            db.commit()
        allowed, started, release = threading.Event(), threading.Event(), threading.Event()
        requests, rejected_requests = [], []
        repair = None
        repair_deadline = None
        prefix = '/Xenova/bge-m3/resolve/4de13258303883538bd53b696b452bf8099f0858/'

        class ModelSource(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                name = self.path.removeprefix(prefix)
                if not self.path.startswith(prefix) or name not in ('tokenizer.json', 'onnx/model_quantized.onnx'):
                    self.send_response(404)
                    self.end_headers()
                    return
                if not allowed.is_set():
                    rejected_requests.append(name)
                    self.send_response(503)
                    self.end_headers()
                    return
                requests.append((name, self.headers.get('Range')))
                path = cache / name
                self.send_response(200)
                self.send_header('Content-Length', str(path.stat().st_size))
                self.end_headers()
                try:
                    with path.open('rb') as stream:
                        first = True
                        while chunk := stream.read(256 * 1024):
                            self.wfile.write(chunk)
                            self.wfile.flush()
                            if first and name.startswith('onnx/') and self.headers.get('Range') is None:
                                started.set()
                                if not release.wait(45):
                                    return
                            first = False
                except (BrokenPipeError, ConnectionResetError):
                    return

        server = ThreadingHTTPServer(('127.0.0.1', 0), ModelSource)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        previous_mirror = self.env.get('RSRS_MIRROR')
        self.env['RSRS_MIRROR'] = 'http://127.0.0.1:' + str(server.server_port)

        def doctor(fix=False):
            argv = ['--json', 'doctor', *(['--fix'] if fix else [])]
            body = {'v': 1, 'id': secrets.token_hex(8), 'method': 'cli.exec', 'args': argv}
            if self.args.runtime_binary and fix:
                # Repair and asset installation belong to the host CLI.
                result = subprocess.run([str(self.args.binary), *argv], env=self.env,
                                        cwd=self.root, capture_output=True, timeout=90)
                require(result.returncode in (0, 1, 2), 'host_doctor_repair_failed')
                reply = {'exit': result.returncode, 'envelope': json.loads(result.stdout)}
                code = 200
            else:
                if self.args.runtime_binary:
                    code, health, _ = self.http(self.url, 'GET', '/api/health')
                    require(code == 200, 'doctor_scope_health_failed')
                    verify_runtime_health(self.args, health, self.root, self.library, self.child.pid)
                    body = scoped_rpc_request(health, argv)
                code, reply, _ = self.http(self.url, 'POST', '/api/rpc', body, self.token)
                if self.args.runtime_binary:
                    verify_rpc_receipt(body, reply)
            envelope = reply.get('envelope', {})
            require(code == 200 and envelope.get('command') == 'doctor'
                    and reply.get('exit') in (0, 1, 2), 'doctor_repair_envelope_invalid')
            rows = {row['name']: row for row in envelope.get('items', [])
                    if row.get('name') in ('embedder', 'model index')}
            require(len(rows) == 2, 'doctor_model_rows_missing')
            return rows

        def wait_index(want, seconds=90):
            deadline = time.monotonic() + seconds
            while time.monotonic() < deadline:
                if want == 'ready':
                    # Exercise the existing repair while TUI-style reads continue.
                    # These reads must not restart model verification or indexing.
                    for command in (['account', 'list'], ['config'], ['agent-config']):
                        if self.args.runtime_binary:
                            self.direct(command)
                        else:
                            self.rpc(command)
                index = self.rpc(['status'])['summary']['retrieval_index']
                states = ('idle', 'scheduled', 'running', 'waiting_model', 'ready', 'missing', 'failed', 'paused', 'stopped')
                self.report['doctor_last_index'] = {
                    'expected': want, 'state': index.get('state') if index.get('state') in states else 'unknown',
                    **{key: index.get(key) if type(index.get(key)) is bool else None
                       for key in ('scheduled', 'running', 'worker_active')},
                }
                if index.get('state') == want:
                    return index
                time.sleep(.2)
            raise Failure('doctor_index_' + want + '_timeout')

        def host_result(result):
            require(result.returncode in (0, 1, 2), 'host_doctor_repair_failed')
            try:
                envelope = json.loads(result.stdout.strip().splitlines()[-1])
            except (ValueError, IndexError):
                raise Failure('host_doctor_repair_envelope_invalid') from None
            require(isinstance(envelope, dict), 'host_doctor_repair_envelope_invalid')
            return envelope

        try:
            self.start()
            if self.args.runtime_binary:
                # Runtime verifies assets; the host owns downloads and Paused recovery.
                wait_index('missing')
                missing = doctor()
                require(missing['embedder']['status'] == 'fail'
                        and missing['model index']['status'] == 'warn'
                        and not rejected_requests and not requests, 'doctor_missing_assets_not_visible')
                command = [str(self.args.binary), '--json', 'doctor', '--fix']
                failed = subprocess.run(command, env=self.env, cwd=self.root, capture_output=True, timeout=90)
                failure = host_result(failed)
                marker = self.root / 'runtime/autostart/maintenance.json'
                require(failed.returncode != 0 and failure.get('status') == 'fail'
                        and '503' in json.dumps(failure) and bool(rejected_requests)
                        and not requests and all(not (model / name).exists() for name in expected_assets),
                        'doctor_download_error_hidden')
                require(marker.is_file() and not marker.is_symlink()
                        and json.loads(marker.read_bytes()).get('phase') == 'Paused', 'doctor_failure_not_paused')
                self.stop()
                require(snapshot() == before and (self.library / 'session.json').read_bytes() == session,
                        'doctor_failed_repair_changed_source_or_session')
                self.passed('doctor_model_failed_download_visible', http_status=503, maintenance='Paused')
                # Recover the failed transaction explicitly before starting another write.
                rejected_count = len(rejected_requests)
                self.direct(['runtime', 'restart'])
                require(not marker.exists() and len(rejected_requests) == rejected_count
                        and not requests, 'doctor_paused_recovery_failed')
                self.start()
                wait_index('missing')
                allowed.set()
                repair_deadline = time.monotonic() + 90
                repair = subprocess.Popen(command, env=self.env, cwd=self.root,
                                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                require(started.wait(45) and repair.poll() is None, 'doctor_retry_did_not_download')
                self.passed('doctor_model_failed_download_retry', synchronous=True, paused_recovered=True)
                paused = marker.read_bytes()
                require(json.loads(paused).get('phase') == 'Paused', 'doctor_active_repair_not_paused')
                busy = subprocess.run(command, env=self.env, cwd=self.root, capture_output=True,
                                      timeout=max(.1, repair_deadline - time.monotonic()))
                busy_result = host_result(busy)
                require(busy.returncode != 0 and busy_result.get('status') == 'fail'
                        and any(word in json.dumps(busy_result).lower() for word in ('maintenance', 'paused'))
                        and marker.read_bytes() == paused and repair.poll() is None,
                        'doctor_competing_repair_not_fenced')
            else:
                wait_index('failed')
                failed = doctor()
                require(all(row['status'] == 'fail' for row in failed.values())
                        and '503' in str(failed['model index'].get('value')), 'doctor_download_error_hidden')
                self.passed('doctor_model_failed_download_visible', http_status=503)
                allowed.set()
                scheduled = doctor(True)
                require(all(row['status'] == 'warn' for row in scheduled.values()), 'doctor_retry_not_scheduled')
                require(started.wait(45), 'doctor_retry_did_not_download')
                self.passed('doctor_model_failed_download_retry')
                busy = doctor(True)
                require(all(row['status'] == 'warn' for row in busy.values()), 'doctor_competing_installer_started')
            # One ignored Range probe and one blocked transfer, with no competing installer.
            model_requests = [range_header for name, range_header in requests
                              if name == 'onnx/model_quantized.onnx']
            require(model_requests == ['bytes=0-0', None], 'doctor_competing_installer_started')
            release.set()
            if repair is not None:
                stdout, _ = repair.communicate(timeout=max(.1, repair_deadline - time.monotonic()))
                repaired = host_result(subprocess.CompletedProcess(command, repair.returncode, stdout))
                require(repair.returncode in (0, 2) and repaired.get('command') == 'doctor'
                        and repaired.get('status') != 'fail' and not marker.exists(), 'host_doctor_repair_not_completed')
                # Host maintenance replaces the owner; resume the fixture's verified child.
                self.stop()
                self.start()
            wait_index('ready', 240)
            ready = doctor()
            require(all(row['status'] == 'ok' for row in ready.values()), 'doctor_ready_model_not_pass')
            require([header for name, header in requests if name == 'onnx/model_quantized.onnx']
                    == model_requests, 'doctor_competing_installer_started')
            self.passed('doctor_model_active_download_no_duplicate', model_downloads=1, range_probes=1)
            require(asset_digests(model) == expected_assets, 'doctor_repaired_asset_digest_mismatch')
            self.passed('doctor_model_repair_ready', asset_digests=expected_assets)
            require(snapshot() == before and (self.library / 'session.json').read_bytes() == session,
                    'doctor_repair_changed_source_or_session')
            recovered = self.rpc(['recall', 'Runtime fixture persisted memory.', '--titles'])['details']
            require([row['id'] for row in recovered] == candidate_ids, 'doctor_repair_changed_candidates')
            self.passed('doctor_model_repair_preserves_source', candidates_unchanged=True)
        finally:
            release.set()
            self.report['doctor_repair_cleanup'] = {'passed': False}
            try:
                try:
                    if repair is not None and repair.poll() is None:
                        try:
                            repair.communicate(timeout=max(.1, repair_deadline - time.monotonic()))
                        except subprocess.TimeoutExpired:
                            repair.kill()
                            repair.communicate(timeout=5)
                            raise Failure('doctor_owned_repair_cleanup_timeout') from None
                finally:
                    self.stop()
                    if self.args.runtime_binary:
                        self.direct(['--runtime-internal', '--stop'])
                self.report['doctor_repair_cleanup']['passed'] = True
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)
                if previous_mirror is None:
                    self.env.pop('RSRS_MIRROR', None)
                else:
                    self.env['RSRS_MIRROR'] = previous_mirror


    def validation_errors(self):
        entry = self.direct(['remember', 'Owned validation fixture.', '--title', 'Validation leaf',
                             '--force', '--importance', 'important'])['summary']['id']
        commands = [
            ['resort', '--spec', '{"ops":[{"id":"aaaaaaaa","parent":"aaaaaaaa"}]}'],
            ['resort', '--spec', '{'], ['resort', '--spec', '{"ops":[]}'],
            ['split', entry, '--go', '--spec', '{"items":[]}'],
            ['split', entry, '--go', '--spec', '{'], ['tree-deepen', '--root', entry],
        ]
        for command in commands:
            result = subprocess.run([str(self.args.binary), '--direct', *command, '--json'],
                                    env=self.env, cwd=self.root, capture_output=True, text=True, timeout=90)
            require(result.returncode == 2, 'direct_validation_exit_not_user_error')
            value = json.loads(result.stdout.strip())
            require(value.get('status') == 'fail', 'direct_validation_status_not_fail')
            require(value['summary'].get('reason') == 'invalid_input'
                    and value['details'].get('error_type') == 'user', 'direct_validation_error_not_typed')
        self.start()
        try:
            for command in commands:
                value = self.rpc(command, expected=2)
                require(value['summary'].get('reason') == 'invalid_input'
                        and value['details'].get('error_type') == 'user', 'rpc_validation_error_not_typed')
        finally:
            self.stop()
        self.passed('runtime_validation_errors_typed', direct_cases=len(commands), rpc_cases=len(commands))

    def host_space_commands(self):
        home = self.root / 'space-command-home'
        library = home / '.rsrs'
        home.mkdir(mode=0o700)
        library.mkdir(mode=0o700)
        config = library / 'client.json'
        config.write_text(json.dumps({'data_dir': str(library), 'api_base': 'https://fixture.invalid',
                                      'custom': 'preserve'}), encoding='utf-8')
        env = self.env.copy()
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        url = 'http://127.0.0.1:' + str(port)
        env.update(HOME=str(home), USERPROFILE=str(home), RSRS_DATA_DIR=str(library),
                   RSRS_RPC_PORT=str(port), XDG_RUNTIME_DIR=str(home / 'runtime'))
        install_published_runtime(self.args.binary, env)
        def cli(args, expected=0):
            result = subprocess.run([str(self.args.binary), '--json', *args], env=env, cwd=home,
                                    capture_output=True, text=True, timeout=90)
            require(result.returncode == expected, 'space_host_cli_exit_mismatch')
            value = json.loads(result.stdout.strip())
            require(value['status'] == ('ok' if expected == 0 else 'fail'), 'space_host_cli_status_mismatch')
            return value
        def health(profile):
            code, actual, _ = self.http(url, 'GET', '/api/health')
            if self.args.runtime_binary:
                require(code == 200, 'space_host_health_failed')
                verify_runtime_health(self.args, actual, library, profile)
            else:
                require(code == 200 and actual['bin'] == self.args.version
                    and hashlib.sha256(Path(actual['exe']).read_bytes()).hexdigest() == self.args.binary_sha256
                    and Path(actual['data_dir']).resolve() == profile.resolve(), 'space_host_runtime_readback_failed')
            return actual['pid']
        try:
            cli(['space', 'list'])
            cli(['runtime', 'start'])
            old_pid = health(library)
            cli(['space', 'create', 'probe'])
            probe = library / 'accounts/probe'
            require(Path(json.loads(config.read_text(encoding='utf-8'))['data_dir']).resolve() == probe.resolve(),
                    'space_create_did_not_select_profile')
            with socket.socket() as listener:
                listener.settimeout(2)
                require(listener.connect_ex(('127.0.0.1', port)) != 0, 'space_create_did_not_stop_runtime')
            cli(['runtime', 'start'])
            require(probe.joinpath('space_owner.json').is_file() and health(probe) != old_pid,
                    'space_create_did_not_take_over_runtime')
            before = config.read_bytes()
            denied = cli(['space', 'remove', 'probe'], 2)
            require(denied['summary']['reason'] == 'invalid_input' and config.read_bytes() == before,
                    'space_remove_without_confirmation_changed_profile')
            cli(['space', 'remove', 'probe', '--yes'], 2)
            require(probe.is_dir(), 'space_removed_active_profile')
            health(probe)
            cli(['space', 'use', 'main'])
            health(library)
            before = config.read_bytes()
            cli(['space', 'use', 'missing'], 2)
            require(config.read_bytes() == before, 'space_failed_switch_changed_configuration')
            health(library)
            cli(['space', 'remove', 'probe', '--yes'])
            require(not probe.exists(), 'space_remove_did_not_remove_profile')
            health(library)
            preserved = json.loads(config.read_text(encoding='utf-8'))
            require(preserved['api_base'] == 'https://fixture.invalid' and preserved['custom'] == 'preserve',
                    'space_host_command_lost_configuration')
        finally:
            cli(['--runtime-internal', '--stop'])
            with socket.socket() as listener:
                listener.settimeout(2)
                require(listener.connect_ex(('127.0.0.1', port)) != 0, 'space_fixture_runtime_not_closed')
        self.passed('host_space_lifecycle', runtime_cleanup=True, configuration_preserved=True)

    def update_check_comparisons(self):
        previous = self.env.get('RSRS_UPDATE_CHECK')
        self.env['RSRS_UPDATE_CHECK'] = '1'
        cache = self.library / 'update_check.json'
        try:
            for latest, ahead, outdated in [('0.0.1', True, False), (self.args.version, False, False),
                                             ('99.0.0', False, True)]:
                cache.write_text(json.dumps({'checked_at': int(time.time()), 'latest': latest, 'ok': True}),
                                 encoding='utf-8')
                result = subprocess.run([str(self.args.binary), '--direct', '--json', 'update-check'],
                                        env=self.env, cwd=self.root, capture_output=True, text=True, timeout=30)
                require(result.returncode == (2 if outdated else 0), 'update_check_exit_mismatch')
                value = json.loads(result.stdout.strip())
                require(value['summary'].get('ahead') is ahead and value['summary'].get('outdated') is outdated
                        and value['summary'].get('cached') is True, 'update_comparison_state_wrong')
                display = value['items'][0]['value']
                require((' -> ' in display) is outdated and ('ahead of published latest' in display) is ahead
                        and bool(value['actions']) is outdated, 'update_comparison_offers_downgrade')
        finally:
            cache.unlink(missing_ok=True)
            if previous is None:
                self.env.pop('RSRS_UPDATE_CHECK', None)
            else:
                self.env['RSRS_UPDATE_CHECK'] = previous
        self.passed('update_check_comparison', states=3)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--binary-sha256', required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--source-sha', required=True)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--report', type=Path)
    add_runtime_arguments(parser)
    args = parser.parse_args()
    args.binary = args.binary.resolve()
    runtime_inputs(args, [args.binary])
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
        smoke.doctor_model_recovery()
        smoke.validation_errors()
        smoke.host_space_commands()
        smoke.update_check_comparisons()
    except RuntimeHealthFailure as error:
        smoke.report['failure_code'] = error.code
        smoke.report['failure_diagnostic'] = error.diagnostic()
    except Exception as error:
        smoke.report['failure_code'] = str(error) if isinstance(error, Failure) else type(error).__name__
    finally:
        smoke.cleanup()
    smoke.report['missing_cases'] = [name for name in REQUIRED if smoke.report['cases'].get(name, {}).get('passed') is not True]
    smoke.report['passed'] = not smoke.report['missing_cases'] and not smoke.report.get('failure_code') and smoke.cloud_clean and smoke.provider_clean
    smoke.report['status'] = 'passed' if smoke.report['passed'] else 'failed'
    smoke.report.update(runtime_report(args, smoke.report['passed']))
    if args.runtime_binary and not smoke.report['standalone_runtime_evidence']:
        smoke.report['passed'] = False
        smoke.report['status'] = 'failed'
    if smoke.created:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(smoke.report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'passed': smoke.report['passed'], 'failure_code': smoke.report.get('failure_code'),
                      'failure_diagnostic': smoke.report.get('failure_diagnostic'),
                      'missing_cases': smoke.report['missing_cases'], 'cloud_cleanup': smoke.report['cloud_cleanup']}))
    return 0 if smoke.report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
