#!/usr/bin/env python3
"""Bounded fixture tests, not a substitute for published CLI/Runtime regression."""
import ast
import copy
import json
import io
from unittest.mock import Mock
import os
import re
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

SOURCE = Path(__file__).with_name('dev-login-interruption-smoke.py').read_text()
TREE = ast.parse(SOURCE)
NAMES = {'original_operation', 'account_recovery_flags', 'terminal_operation',
         'process_group_members', 'interrupt_owned_control', 'stop_owned_control', 'login_continuation_receipt',
         'runtime_stop_receipt', 'fixture_runtime_owners', 'key_continuation_receipt', 'remove_fixture_super'}


def require(value, message):
    if not value:
        raise RuntimeError(message)


# Load the actual pure helpers without importing optional native/crypto fixtures.
exec(compile(ast.Module(body=[node for node in TREE.body
                             if isinstance(node, ast.FunctionDef) and node.name in NAMES],
                        type_ignores=[]), '<actual-fixture-helpers>', 'exec'), globals())


class JournalContract(unittest.TestCase):
    def setUp(self):
        self.root = Path('/tmp/synthetic-interruption-contract').resolve()
        self.id = str(uuid.uuid4())
        self.addr = 'http://127.0.0.1:12345'
        self.record = {'operation_id': self.id, 'idempotency_key': self.id,
                       'profile': str(self.root), 'root': str(self.root),
                       'alias': 'login-' + uuid.uuid4().hex, 'phase': 'awaiting_verification',
                       'account': {'user': 'synthetic', 'addr': self.addr, 'register': False, 'login': {'migrate_vault': True,
                           'publication_done': False, 'vault_done': False, 'password_done': False,
                           'publication_pending': False, 'publication_step': None}}}
        self.record['candidate'] = list(json.dumps({'user': 'synthetic', 'addr': self.addr,
            'token': 'synthetic-token', 'keyring_account': self.record['alias']}).encode())
        self.journal = {'schema_version': 2,
                        'active': {'operation_id': self.id, 'alias': self.record['alias']},
                        'operations': [self.record]}

    def test_before_publication_is_bound_without_mutation(self):
        before = copy.deepcopy(self.journal)
        self.assertIs(original_operation(self.journal, self.root, 'before_publish', self.addr), self.record)
        self.assertEqual(before, self.journal)

    def test_after_publication_requires_exact_pending_vault(self):
        self.record['account']['login'].update(publication_pending=True, publication_step='vault')
        self.assertIs(original_operation(self.journal, self.root, 'after_publish', self.addr), self.record)
        with self.assertRaisesRegex(RuntimeError, 'publication_checkpoint'):
            original_operation(self.journal, self.root, 'before_publish', self.addr)
        main = next(n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name == 'main')
        cli_node = next(n for n in ast.walk(main) if isinstance(n, ast.FunctionDef) and n.name == 'cli')
        runner = Mock(return_value=subprocess.CompletedProcess([], 0, b'{}', b''))
        from types import SimpleNamespace
        scope = dict(env={'RSRS_SUPER': 'synthetic-legacy-super'}, keys=object(),
                     report={'stage': 'after_publish'}, old_super='synthetic-legacy-super',
                     args=SimpleNamespace(binary=Path('fixture-cli')),
                     subprocess=SimpleNamespace(run=runner))
        exec(compile(ast.Module(body=[cli_node], type_ignores=[]), '<actual-fixture-cli>', 'exec'), scope)
        scope['cli']('--json', 'account-result')
        self.assertNotIn('RSRS_SUPER', runner.call_args.kwargs['env'])
        scope['keys'] = None
        scope['cli']('--json', 'account-result')
        self.assertEqual(runner.call_args.kwargs['env']['RSRS_SUPER'], 'synthetic-legacy-super')
        scope['keys'] = object()
        scope['report']['stage'] = 'initial_authentication'
        scope['cli']('--json', 'remember')
        self.assertEqual(runner.call_args.kwargs['env']['RSRS_SUPER'], 'synthetic-legacy-super')

    def test_wrong_original_and_unknown_phase_fail_closed(self):
        mutations = [
            lambda j: j.update(schema_version=1),
            lambda j: j['active'].update(operation_id=None),
            lambda j: j['active'].update(alias='unrelated'),
            lambda j: j['operations'].append(copy.deepcopy(j['operations'][0])),
            lambda j: j['operations'][0].update(idempotency_key=str(uuid.uuid4())),
            lambda j: j['operations'][0].update(profile='/tmp/other'),
            lambda j: j['operations'][0].update(root='/tmp/other'),
            lambda j: j['operations'][0].update(phase='remote_unknown'),
            lambda j: j['operations'][0]['account'].update(register=True),
            lambda j: j['operations'][0]['account'].update(user='different'),
            lambda j: j['operations'][0]['account'].update(addr='http://other.invalid'),
            lambda j: j['operations'][0]['account']['login'].update(migrate_vault=False),
            lambda j: j['operations'][0]['account']['login'].update(publication_done=True),
            lambda j: j['operations'][0]['account']['login'].update(vault_done=True),
            lambda j: j['operations'][0]['account']['login'].update(password_done=True),
            lambda j: j['operations'][0]['account']['login'].update(publication_step='password'),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(mutation=index):
                candidate = copy.deepcopy(self.journal)
                mutate(candidate)
                with self.assertRaises((RuntimeError, ValueError)):
                    original_operation(candidate, self.root, 'before_publish', self.addr)

    def test_only_public_original_operation_commands(self):
        for action in ('account-result', 'account-rollback'):
            flags = account_recovery_flags(action, self.record)
            self.assertEqual(flags[:3], ['--json', 'runtime', action])
            self.assertEqual(flags[3:7], ['--operation-id', self.id, '--source-profile', str(self.root)])
            self.assertEqual('--confirm' in flags, action == 'account-rollback')
        for action in ('start', 'login', 'migrate', 'auth-result'):
            with self.assertRaises(RuntimeError):
                account_recovery_flags(action, self.record)

    def test_terminal_receipt_retained_not_journal_deleted(self):
        for phase in ('rolled_back', 'committed'):
            terminal = copy.deepcopy(self.journal)
            terminal['active'] = None
            terminal['operations'][0]['phase'] = phase
            terminal_operation(terminal, self.record, phase)
            with self.assertRaises(RuntimeError):
                terminal_operation(terminal, self.record, 'unknown')
            terminal['active'] = self.journal['active']
            with self.assertRaises(RuntimeError):
                terminal_operation(terminal, self.record, phase)

    def test_continuation_requires_original_identity_and_actual_required_input(self):
        for outcome in ('awaiting_input', 'committed'):
            summary = {'operation_id': self.id, 'source_profile': str(self.root), 'outcome': outcome,
                       'login': {'user': 'synthetic', 'addr': self.addr,
                                 'required_inputs': ['super_password'] if outcome == 'awaiting_input' else []}}
            login_continuation_receipt(summary, self.id, self.root, self.addr, outcome)
            for field, wrong in (('operation_id', str(uuid.uuid4())), ('source_profile', '/other'),
                                 ('outcome', 'unknown')):
                with self.subTest(outcome=outcome, field=field), self.assertRaises(RuntimeError):
                    login_continuation_receipt(dict(summary, **{field: wrong}), self.id, self.root, self.addr, outcome)
            for field, wrong in (('user', 'other'), ('addr', 'http://other.invalid'),
                                 ('required_inputs', ['host_credentials'])):
                value = copy.deepcopy(summary)
                value['login'][field] = wrong
                with self.subTest(outcome=outcome, field=field), self.assertRaises(RuntimeError):
                    login_continuation_receipt(value, self.id, self.root, self.addr, outcome)

    def test_real_fixture_keeps_required_failure_assertions(self):
        for assertion in ('legacy_original_profile_not_restored', 'legacy_interrupted_credential_not_deleted',
                          'original_profile_not_restored', 'interrupted_native_credential_not_deleted',
                          'interrupted_native_password_not_deleted', 'fresh_login_replayed_authentication',
                          'unknown_rollback_deleted_credentials', 'unknown_result_released_maintenance',
                          'unknown_result_replayed_effect', 'migration_effects_not_exactly_once',
                          'original_ciphertexts_changed', 'original_source_changed'):
            self.assertIn('"' + assertion + '"', SOURCE)
        self.assertIn('start_new_session=True', SOURCE)
        self.assertLess(SOURCE.index('= interrupt_owned_control(child)'),
                        SOURCE.index('release.set()', SOURCE.index('= interrupt_owned_control(child)')))
        self.assertEqual(SOURCE.count('if not release.wait(120):'), 2)
        self.assertEqual(SOURCE.count('if state.get("barrier_failed"):'), 2)
        self.assertEqual(SOURCE.count('state["barrier_failed"] = True'), 2)
        self.assertNotIn('child.send_signal(', SOURCE)
        self.assertNotIn('.unlink(', SOURCE)
        self.assertNotIn('pop("operation_id"', SOURCE)

    def test_key_continuation_requires_original_identity_and_missing_super(self):
        for outcome in ('awaiting_input', 'committed'):
            summary = {'operation_id': self.id, 'source_profile': str(self.root), 'outcome': outcome}
            summary.update({'operation': {'kind': 'super_reset'}, 'required_inputs': ['super_password']}
                           if outcome == 'awaiting_input' else {'ok': True, 'super': 'synthetic-new-super'})
            key_continuation_receipt(summary, self.id, self.root, outcome)
            wrong_fields = [('operation_id', str(uuid.uuid4())), ('source_profile', '/other'), ('outcome', 'unknown')]
            wrong_fields += ([('required_inputs', []), ('operation', {'kind': 'fivekeys'}), ('super', 'exposed')]
                             if outcome == 'awaiting_input' else [('super', None), ('ok', False)])
            for field, wrong in wrong_fields:
                with self.subTest(outcome=outcome, field=field), self.assertRaises(RuntimeError):
                    key_continuation_receipt(dict(summary, **{field: wrong}), self.id, self.root, outcome)

    def test_key_fixture_deletes_only_bound_super_and_keeps_password(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'session.json'
            alias = 'login-' + uuid.uuid4().hex
            session = {'user': 'synthetic', 'addr': self.addr, 'vault_version': 4,
                       'keyring_backend': 'secret_service', 'keyring_account': alias}
            attributes = lambda service, slot: {'target': 'default', 'service': service,
                                               'username': slot, 'application': 'rust-keyring'}
            for invalid in (None, 'user', 'addr', 'vault_version', 'keyring_backend', 'keyring_account',
                            'super', 'attributes', 'credential', 'collision'):
                candidate = dict(session)
                if invalid in session:
                    candidate[invalid] = 'other'
                if invalid == 'super':
                    candidate['super'] = 'inline-secret'
                path.write_text(json.dumps(candidate), encoding='utf-8')
                before = path.read_bytes()
                super_item, pass_item, keys = Mock(), Mock(), Mock()
                super_item.get_secret.return_value = b'wrong' if invalid == 'credential' else b'synthetic-old-super'
                pass_item.get_secret.return_value = b'synthetic-login-password'
                super_item.get_attributes.return_value = attributes('rsrs', 'super:' + alias)
                pass_item.get_attributes.return_value = attributes('rsrs', 'pass:' + alias)
                if invalid == 'attributes':
                    super_item.get_attributes.return_value['service'] = 'other'
                if invalid == 'collision':
                    keys._find.side_effect = RuntimeError('fixture_secret_service_entry_ambiguous')
                else:
                    keys._find.side_effect = [super_item, pass_item, None, pass_item]
                keys.attributes.side_effect = attributes
                if invalid:
                    with self.subTest(invalid=invalid), self.assertRaises(RuntimeError):
                        remove_fixture_super(keys, path, Path(td), self.addr, 'synthetic-old-super')
                    super_item.delete.assert_not_called()
                else:
                    remove_fixture_super(keys, path, Path(td), self.addr, 'synthetic-old-super')
                    super_item.delete.assert_called_once_with()
                    keys.verify_owner.assert_called_once_with()
                pass_item.delete.assert_not_called()
                self.assertEqual(path.read_bytes(), before)


class RuntimeCleanupContract(unittest.TestCase):
    def test_finally_rejects_pending_exit_and_surviving_owner(self):
        function = next(node for node in TREE.body
                        if isinstance(node, ast.FunctionDef) and node.name == 'host_login_continuation')
        cleanup = next(node.finalbody for node in function.body if isinstance(node, ast.Try))
        from types import SimpleNamespace
        receipt = json.dumps({'status': 'ok', 'summary': {'state': 'stopped'}}).encode()
        for exit_code, owners, passed in ((2, [], False), (0, [123], False), (0, [], True)):
            with self.subTest(exit=exit_code, owners=owners):
                observation = {}
                runner = Mock(return_value=subprocess.CompletedProcess([], exit_code, receipt))
                scope = dict(globals(), binary=Path('fixture-cli'), command_env={},
                             directory=Path('fixture'), images=[Path('fixture-cli')], observation=observation,
                             key_observation={},
                             subprocess=SimpleNamespace(run=runner), fixture_runtime_owners=Mock(return_value=owners))
                code = compile(ast.Module(body=cleanup, type_ignores=[]), '<actual-cleanup>', 'exec')
                if passed:
                    exec(code, scope)
                    self.assertTrue(observation['runtime_cleanup']['no_live_owner'])
                else:
                    with self.assertRaisesRegex(RuntimeError, 'owned_runtime_cleanup_failed'):
                        exec(code, scope)
                self.assertIs(observation['runtime_cleanup']['passed'], passed)
                self.assertIn('--json', runner.call_args.args[0])

    def test_only_explicit_successful_stop_receipt_is_accepted(self):
        good = {'status': 'ok', 'summary': {'state': 'stopped'}, 'errors': []}
        runtime_stop_receipt(subprocess.CompletedProcess([], 0, json.dumps(good).encode()))
        for exit_code, receipt in ((2, good), (1, good),
                (0, {**good, 'status': 'pending'}),
                (0, {**good, 'summary': {'state': 'pending'}}),
                (0, {**good, 'summary': {'state': 'unknown'}}),
                (0, {**good, 'errors': ['stop failed']}), (0, {})):
            with self.subTest(exit=exit_code, receipt=receipt):
                with self.assertRaisesRegex(RuntimeError, 'owned_runtime_cleanup_failed'):
                    runtime_stop_receipt(subprocess.CompletedProcess([], exit_code, json.dumps(receipt).encode()))
        with self.assertRaises(json.JSONDecodeError):
            runtime_stop_receipt(subprocess.CompletedProcess([], 0, b'not-json'))


class BarrierContract(unittest.TestCase):
    def test_reset_uses_authenticated_vault_storage_and_readback(self):
        main = next(node for node in TREE.body if isinstance(node, ast.FunctionDef) and node.name == 'main')
        handler = next(node for node in ast.walk(main) if isinstance(node, ast.ClassDef) and node.name == 'Handler')
        state = {'vault': {'version': 4, 'wrapped_urk': 'original'}, 'posts': 0, 'gets': 0, 'barrier': None}
        scope = dict(BaseHTTPRequestHandler=object, json=json, state=state)
        exec(compile(ast.Module(body=[handler], type_ignores=[]), '<actual-vault-handler>', 'exec'), scope)
        instance = scope['Handler']()
        instance.path = '/api/self/vault'
        replacement = {'version': 4, 'wrapped_urk': 'replacement'}
        body = json.dumps(replacement).encode()
        instance.headers = {'Content-Length': str(len(body))}
        instance.send_error, instance.reply = Mock(), Mock()
        for method in (instance.do_GET, instance.do_POST):
            instance.rfile = io.BytesIO(body)
            before = copy.deepcopy(state)
            method()
            instance.send_error.assert_called_with(401)
            self.assertEqual(state, before)
            instance.reply.assert_not_called()
        instance.headers['Authorization'] = 'Bearer synthetic-token'
        instance.rfile = io.BytesIO(body)
        instance.do_POST()
        self.assertEqual(state['vault'], replacement)
        self.assertEqual(state['posts'], 1)
        instance.do_GET()
        instance.reply.assert_called_with(replacement)
        self.assertEqual(state['posts'], 1)

    def test_timeout_latches_all_observation_and_mutation_endpoints_closed(self):
        main = next(node for node in TREE.body if isinstance(node, ast.FunctionDef) and node.name == 'main')
        handler = next(node for node in ast.walk(main) if isinstance(node, ast.ClassDef) and node.name == 'Handler')
        for barrier in ('before_publish', 'after_publish'):
            with self.subTest(barrier=barrier):
                state = {'vault': {'original': True}, 'posts': 0, 'gets': 1, 'barrier': barrier}
                release, reached = Mock(), Mock()
                release.wait.return_value = False
                scope = {'BaseHTTPRequestHandler': object, 'json': json, 'state': state,
                         'release': release, 'reached': reached}
                exec(compile(ast.Module(body=[handler], type_ignores=[]), '<actual-handler>', 'exec'), scope)
                instance = scope['Handler']()
                instance.path = '/api/self/vault'
                body = json.dumps({'candidate': True}).encode()
                instance.headers = {'Content-Length': str(len(body)), 'Authorization': 'Bearer synthetic-token'}
                instance.rfile = io.BytesIO(body)
                instance.send_error, instance.reply = Mock(), Mock()
                if barrier == 'before_publish':
                    instance.do_GET()
                else:
                    instance.do_POST()
                self.assertTrue(state['barrier_failed'])
                release.wait.assert_called_once_with(120)
                reached.set.assert_called_once()
                instance.reply.assert_not_called()
                instance.send_error.assert_called_once_with(503)
                frozen = copy.deepcopy(state)
                instance.path = '/api/self/password'
                instance.do_POST()
                instance.path = '/api/self/vault'
                instance.do_GET()
                self.assertEqual(state, frozen)
                self.assertEqual(instance.send_error.call_count, 3)
                instance.reply.assert_not_called()


@unittest.skipUnless(sys.platform.startswith('linux') and hasattr(os, 'pidfd_open'), 'Linux pidfd required')
class ProcessContract(unittest.TestCase):
    def test_cleanup_detects_environment_only_owner_and_equals_argument_after_image_match(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / 'selected-profile'
            for arguments, environment in (([], dict(os.environ, RSRS_DATA_DIR=str(target))),
                    (['--data-dir=' + str(target)], dict(os.environ, RSRS_DATA_DIR=temp + '-unrelated'))):
                with self.subTest(arguments=arguments):
                    child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)', *arguments],
                                             env=environment)
                    try:
                        self.assertEqual(fixture_runtime_owners(Path(temp), [sys.executable]), [child.pid])
                        self.assertEqual(fixture_runtime_owners(Path(temp), [Path(temp) / 'other-image']), [])
                        child.terminate()
                        child.wait(timeout=5)
                        self.assertEqual(fixture_runtime_owners(Path(temp), [sys.executable]), [])
                    finally:
                        if child.poll() is None:
                            child.kill()
                        child.wait(timeout=5)

    def test_cleanup_detects_live_owner_in_selected_target_and_ignores_other_fixture(self):
        with tempfile.TemporaryDirectory() as temp, tempfile.TemporaryDirectory() as other:
            target = Path(temp) / 'selected-profile'
            child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)',
                                      '--data-dir', str(target)])
            unrelated = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)',
                                          '--data-dir', other])
            try:
                self.assertEqual(fixture_runtime_owners(Path(temp), [sys.executable]), [child.pid])
                child.terminate()
                child.wait(timeout=5)
                self.assertEqual(fixture_runtime_owners(Path(temp), [sys.executable]), [])
                self.assertIsNone(unrelated.poll())
            finally:
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=5)
                unrelated.terminate()
                unrelated.wait(timeout=5)

    def test_private_helper_exit_proven_and_unrelated_process_survives(self):
        with tempfile.TemporaryDirectory() as temp:
            ready = Path(temp) / 'ready'
            helper = ('import os,signal,time; from pathlib import Path; '
                      'signal.signal(signal.SIGINT,signal.SIG_DFL); '
                      f'Path({str(ready)!r}).write_text(str(os.getpid())); time.sleep(60)')
            leader = ('import signal,subprocess,sys,time; '
                      'signal.signal(signal.SIGINT,signal.SIG_DFL); '
                      f'subprocess.Popen([sys.executable,"-c",{helper!r},"--host-control-internal"]); '
                      'time.sleep(60)')
            unrelated = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
            child = subprocess.Popen([sys.executable, '-c', leader], start_new_session=True,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                deadline = time.monotonic() + 10
                while not ready.exists() and time.monotonic() < deadline:
                    time.sleep(.02)
                self.assertTrue(ready.exists())
                proof = interrupt_owned_control(child)
                self.assertTrue(proof['helper_exit_confirmed'])
                self.assertTrue(proof['cli_reaped'])
                self.assertEqual(set(proof['members']), {child.pid, int(ready.read_text())})
                self.assertIsNone(unrelated.poll())
            finally:
                if child.poll() is None:
                    os.killpg(child.pid, signal.SIGKILL)
                child.communicate(timeout=5)
                unrelated.terminate()
                unrelated.wait(timeout=5)

    def test_failure_cleanup_uses_bound_helper_after_cli_reaped(self):
        with tempfile.TemporaryDirectory() as temp:
            ready = Path(temp) / 'helper'
            leave = Path(temp) / 'leave'
            helper = ('import os,time; from pathlib import Path; '
                      f'Path({str(ready)!r}).write_text(str(os.getpid())); time.sleep(60)')
            leader = ('import subprocess,sys,time; from pathlib import Path; '
                      f'subprocess.Popen([sys.executable,"-c",{helper!r},"--host-control-internal"]); '
                      f'\nwhile not Path({str(leave)!r}).exists(): time.sleep(.01)')
            child = subprocess.Popen([sys.executable, '-c', leader], start_new_session=True,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                deadline = time.monotonic() + 10
                while not ready.exists() and time.monotonic() < deadline:
                    time.sleep(.02)
                self.assertTrue(ready.exists())
                members = process_group_members(child.pid)
                self.assertEqual(set(members), {child.pid, int(ready.read_text())})
                child._fixture_pidfds = [os.pidfd_open(pid) for pid in members]
                leave.touch()
                self.assertEqual(child.wait(timeout=5), 0)
                stop_owned_control(child)
                self.assertFalse(child._fixture_pidfds)
                self.assertTrue(all(row['state'] == 'Z' for row in process_group_members(child.pid).values()))
            finally:
                if getattr(child, '_fixture_pidfds', None):
                    stop_owned_control(child)
                elif child.poll() is None:
                    os.killpg(child.pid, signal.SIGKILL)
                child.communicate(timeout=5)

    def test_partial_pidfd_snapshot_fails_closed_without_signalling_unknown_helper(self):
        with tempfile.TemporaryDirectory() as temp:
            ready = Path(temp) / 'helper'
            helper = ('import os,time; from pathlib import Path; '
                      f'Path({str(ready)!r}).write_text(str(os.getpid())); time.sleep(60)')
            leader = ('import subprocess,sys,time; '
                      f'subprocess.Popen([sys.executable,"-c",{helper!r},"--host-control-internal"], '
                      'stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); time.sleep(60)')
            child = subprocess.Popen([sys.executable, '-c', leader], start_new_session=True,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            helper_fd = None
            try:
                deadline = time.monotonic() + 10
                while not ready.exists() and time.monotonic() < deadline:
                    time.sleep(.02)
                self.assertTrue(ready.exists())
                helper_fd = os.pidfd_open(int(ready.read_text()))
                child._fixture_pidfds = [os.pidfd_open(child.pid)]  # Inject partial bind failure.
                with self.assertRaisesRegex(RuntimeError, 'cleanup_untracked_group_member'):
                    stop_owned_control(child)
                poller = select.poll()
                poller.register(helper_fd, select.POLLIN)
                self.assertFalse(poller.poll(0), 'Unknown helper must not be signalled by numeric PID')
            finally:
                if helper_fd is not None:
                    signal.pidfd_send_signal(helper_fd, signal.SIGKILL)
                    poller = select.poll()
                    poller.register(helper_fd, select.POLLIN)
                    self.assertTrue(poller.poll(5000))
                    os.close(helper_fd)
                if child.poll() is None:
                    child.kill()
                child.communicate(timeout=5)

    def test_non_session_child_rejected_without_signal(self):
        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
        try:
            with self.assertRaisesRegex(RuntimeError, 'session_not_owned'):
                interrupt_owned_control(child)
            self.assertIsNone(child.poll())
        finally:
            child.terminate()
            child.wait(timeout=5)


class ReportContract(unittest.TestCase):
    def reporter(self):
        from contextlib import contextmanager
        from types import SimpleNamespace
        scope = dict(contextmanager=contextmanager, subprocess=subprocess, json=json)
        nodes = [node for node in TREE.body if
            isinstance(node, ast.FunctionDef) and node.name == 'fixture_report' or
            isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'FAILURE_CODES' for t in node.targets)]
        exec(compile(ast.Module(body=nodes, type_ignores=[]), '<actual-report>', 'exec'), scope)
        return scope['fixture_report'], SimpleNamespace

    def test_all_phases_write_safe_report_without_swallowing_failure(self):
        reporter, namespace = self.reporter()
        for phase in ('bootstrap', 'runtime_install', 'host_login_continue', 'initial_authentication', 'before_publish',
                      'owned_child_cleanup', 'runtime_cleanup', 'credential_cleanup', 'server_cleanup'):
            for error in (RuntimeError('secret-token-and-path'), ValueError('secret-token-and-path'),
                          RuntimeError('original_operation_identity_mismatch'),
                          subprocess.TimeoutExpired('secret-command', 1, output=b'secret-output')):
                with self.subTest(phase=phase, kind=type(error).__name__), tempfile.TemporaryDirectory() as td:
                    report = {'passed': True, 'cases': {}}
                    with self.assertRaises(type(error)) as raised:
                        with reporter(namespace(root=Path(td)), report):
                            report['stage'] = phase
                            raise error
                    self.assertIs(raised.exception, error)
                    saved = json.loads((Path(td) / 'interruption-coverage.json').read_text())
                    self.assertFalse(saved['passed'])
                    self.assertEqual(saved['stage'], phase)
                    self.assertIn(saved['failure_code'], ('unclassified_failure', 'subprocess_timeout',
                                                          'original_operation_identity_mismatch'))
                    self.assertNotIn('secret-', json.dumps(saved))

    def test_cleanup_failure_never_keeps_pass(self):
        reporter, namespace = self.reporter()
        with tempfile.TemporaryDirectory() as td:
            report = {'passed': True}
            with self.assertRaises(RuntimeError):
                with reporter(namespace(root=Path(td)), report):
                    report['stage'] = 'credential_cleanup'
                    raise RuntimeError('native_fixture_cleanup_failed')
            self.assertEqual(report['failure_code'], 'native_fixture_cleanup_failed')
            self.assertFalse(json.loads((Path(td) / 'interruption-coverage.json').read_text())['passed'])

    def test_success_and_outer_scope_cover_setup_and_cleanup(self):
        reporter, namespace = self.reporter()
        with tempfile.TemporaryDirectory() as td:
            report = {'passed': False}
            with reporter(namespace(root=Path(td)), report):
                report.update(passed=True, stage='complete')
            self.assertTrue(json.loads((Path(td) / 'interruption-coverage.json').read_text())['passed'])
        main = next(n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name == 'main')
        outer = next(n for n in main.body if isinstance(n, ast.With))
        body = ast.unparse(outer)
        for item in ('install_published_runtime', 'stop_owned_control', 'keys.cleanup()', 'server.shutdown()'):
            self.assertIn(item, body)
        self.assertNotIn('diagnostic[:1500]', SOURCE)


if __name__ == '__main__':
    unittest.main()
