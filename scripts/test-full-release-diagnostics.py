"""Offline redaction and fail-closed regression tests; never execute the product."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
import native_fixture_process as native

spec = importlib.util.spec_from_file_location('runtime_smoke', Path(__file__).with_name('dev-runtime-smoke.py'))
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)
SECRET = 'secret-token-password-user-server-/private/path-123'


class DiagnosticsTests(unittest.TestCase):
    def test_exit_redaction(self):
        for reason in (SECRET, {'token': SECRET}, [SECRET], None, 'invalid_input', 'runtime_error', 'request_outcome_unknown'):
            value = {'summary': {'reason': reason, 'password': SECRET}, 'errors': [SECRET], 'details': {'token': SECRET}}
            result = types.SimpleNamespace(stdout=json.dumps(value), stderr=SECRET, returncode=2)
            diagnostic = runtime.exit_diagnostic(SECRET, 1, result)
            self.assertNotIn(SECRET, json.dumps(diagnostic))
            self.assertEqual(diagnostic['case_id'], 'owned_cli')
            self.assertEqual(diagnostic['structured_reason'], reason if isinstance(reason, str) and reason in runtime.CLI_REASONS else 'unknown')
            self.assertEqual((diagnostic['expected_exit'], diagnostic['actual_exit']), (1, 2))
        for stdout in (SECRET, '[]', '{}', '', '{', 'null', '{"summary":null}'):
            result.stdout = stdout
            self.assertEqual(runtime.exit_diagnostic('nonloopback_dns', 1, result)['structured_reason'], 'unknown')
        for case_id in runtime.DIRECT_CASE_IDS:
            self.assertEqual(runtime.exit_diagnostic(case_id, 0, result)['case_id'], case_id)

        from dev_migration_diagnostics import migration_execution_state
        import sqlite3
        import uuid
        from contextlib import closing
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            home = base / 'home'; home.mkdir()
            root = home / '.rsrs'; root.mkdir()
            source, account, operation = 'a' * 64, 'imported-test', str(uuid.uuid4())
            arguments = ('migrate', '--source', source, '--account', account)
            envelope = {'errors': ['migration_outcome_unknown operation_id=' + operation + '; migration_stage=exchange']}
            env = {'HOME': str(home), 'RSRS_DATA_DIR': str(root)}
            original = dict(operation_id=operation, source_id=source, account=account, key=SECRET)
            host = root / 'runtime/autostart/migrations'; host.mkdir(parents=True)
            (host / 'original.json').write_text(json.dumps({'operation': original, 'sent': True,
                'finished': False, 'was_serving': True, 'store_ready': False, 'session': SECRET}), encoding='utf8')
            stage = home / '.rsrs-migration-staging' / str(uuid.uuid4()); stage.mkdir(parents=True)
            intents = home / '.rsrs-migration-intents'; intents.mkdir()
            path = intents / (operation + '.json')
            frame = dict(original=original, phase='copying', stage=str(stage), session_digest=SECRET)
            path.write_text(json.dumps(frame) + '\n', encoding='utf8')
            (root / 'session.json').write_text(SECRET, encoding='utf8')
            with closing(sqlite3.connect(stage / 'onememory.db')) as database:
                database.execute('CREATE TABLE private_payload(body TEXT)')
                database.execute('INSERT INTO private_payload VALUES(?)', (SECRET,))
                database.commit()
            profile_spec = importlib.util.spec_from_file_location('profile_migration_smoke', Path(__file__).with_name('dev-profile-migration-smoke.py'))
            profile = importlib.util.module_from_spec(profile_spec)
            profile_spec.loader.exec_module(profile)
            smoke = profile.Smoke.__new__(profile.Smoke)
            default = smoke.default_env(dict(env, RSRS_SUPER=SECRET, RSRS_RUNTIME_BIN=SECRET))
            self.assertNotIn('RSRS_DATA_DIR', default)
            self.assertNotIn('RSRS_RUNTIME_BIN', default)
            for diagnostic_env in (env, dict(default, RSRS_SUPER=SECRET), dict(env, RSRS_DATA_DIR='')):
                state = migration_execution_state(base, diagnostic_env, arguments, envelope)
                self.assertEqual((state['status'], state['host_record'], state['intent_phase']), ('collected', 'matched', 'copying'))
                self.assertEqual(state['staging_databases']['onememory.db'], {'state': 'ok'})
                self.assertTrue(state['sent'])
                self.assertFalse(state['destination_exists'])
                self.assertNotIn(SECRET, json.dumps(state))
                self.assertNotIn(str(home), json.dumps(state))
            with closing(sqlite3.connect(root / 'lock.db')) as lock:
                lock.execute('CREATE TABLE lock_probe(value INTEGER)'); lock.commit()
                lock.execute('BEGIN EXCLUSIVE')
                state = migration_execution_state(base, env, arguments, envelope)
                self.assertEqual(state['installation_lock']['state'], 'busy')
                lock.rollback()
            for invalid in (dict(frame, phase=SECRET), dict(frame, stage=str(base / 'outside'))):
                path.write_text(json.dumps(invalid) + '\n', encoding='utf8')
                state = migration_execution_state(base, env, arguments, envelope)
                self.assertEqual(state, {'status': 'invalid_or_unavailable'})
                self.assertNotIn(SECRET, json.dumps(state))
            self.assertEqual(migration_execution_state(base, env, arguments, {}), {'status': 'operation_binding_missing'})

    def test_direct_still_fails_and_success_unchanged(self):
        smoke = runtime.Smoke.__new__(runtime.Smoke)
        smoke.args = types.SimpleNamespace(binary=SECRET)
        smoke.env, smoke.root, smoke.report = {}, Path('.'), {}
        value = dict(command='cli', status='fail', summary={'reason': 'invalid_input'}, items=[], actions=[], errors=[SECRET], details={})
        result = types.SimpleNamespace(stdout=json.dumps(value), stderr=SECRET, returncode=2)
        with patch.object(runtime.subprocess, 'run', return_value=result):
            with self.assertRaisesRegex(runtime.Failure, '^owned_cli_exit_mismatch$'):
                smoke.direct([SECRET], expected=1, case_id='nonloopback_dns')
            self.assertNotIn(SECRET, json.dumps(smoke.report))
            self.assertEqual(smoke.report['failure_diagnostic']['case_id'], 'nonloopback_dns')
            result.returncode = 1
            self.assertEqual(smoke.direct([SECRET], expected=1), value)

        from unittest.mock import Mock
        for standalone in (False, True):
            with self.subTest(standalone=standalone):
                smoke.args.runtime_binary = self.image if standalone else None
                smoke.root, smoke.library = self.root, self.root / 'library'
                smoke.user, smoke.password, smoke.attempted = 'owned-user', SECRET, False
                smoke.http = Mock(return_value=(200, {'source_revision': 'a' * 40}, {}))
                smoke.passed, smoke.start = Mock(), Mock()
                profile = self.root / 'accounts/runtime-smoke' if standalone else smoke.library
                probe = {'ready': True, 'inference_completed': True, 'fresh_session': True,
                         'dimensions': 1024, 'selected': 'cpu'}
                def direct(args, **kwargs):
                    if args[0] == 'space':
                        self.assertFalse(profile.exists())
                        return {'details': {'dir': str(profile)}}
                    if args[0] == 'config':
                        return {'summary': {'data_dir': str(profile), 'addr': runtime.DEV}}
                    if args[0] == 'register':
                        self.assertTrue(smoke.attempted)
                        return {'summary': {'user': smoke.user}}
                    return {'details': {'backend_load': {'evidence': probe}}, 'summary': probe}
                with patch.dict(os.environ, {'RSRS_DEV_SERVER_SHA': 'a' * 40,
                                             'RSRS_DEV_SERVER_ADDR': runtime.DEV}), \
                     patch.object(smoke, 'direct', side_effect=direct) as executed:
                    smoke.account()
                commands = [call.args[0] for call in executed.call_args_list]
                self.assertEqual([args[0] for args in commands],
                                 (['space'] if standalone else []) + ['config', 'config', 'model', 'register', 'model'])
                self.assertEqual(commands[int(standalone)], ['config', '--data-dir', str(profile),
                                 '--addr', runtime.DEV, '--autosync', 'false', '--cure-auto', 'false'])
                smoke.passed.assert_called_once_with('data_dir_persisted')
                smoke.start.assert_called_once_with()

    def test_health_unknown_reason_is_generic(self):
        for error in (RuntimeError(SECRET), AssertionError(SECRET), KeyError(SECRET), type(SECRET, (Exception,), {})(SECRET)):
            with patch.object(native, '_verify_runtime_health', side_effect=error):
                with self.assertRaises(native.RuntimeHealthFailure) as caught:
                    native.verify_runtime_health(None, None, None, None)
                self.assertEqual(caught.exception.diagnostic(), {'failure_code': 'runtime_health_verification_failed', 'failed_fields': []})
        failure = native.RuntimeHealthFailure(SECRET, ['pid', SECRET])
        self.assertEqual(failure.diagnostic(), {'failure_code': 'runtime_health_verification_failed', 'failed_fields': ['pid']})
        self.assertNotIn(SECRET, str(failure))

    def test_outbox_failure_report_keeps_failed_exit(self):
        import contextlib
        import io
        spec = importlib.util.spec_from_file_location('outbox_smoke', Path(__file__).with_name('dev-outbox-smoke.py'))
        outbox = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(outbox)
        args = types.SimpleNamespace(runtime_binary=None, root=Path(SECRET))
        for failure in (native.RuntimeHealthFailure('runtime_health_fields_mismatch', ['pid', SECRET]),
                        native.RuntimeHealthFailure(SECRET)):
            output = io.StringIO()
            with patch.object(outbox.argparse.ArgumentParser, 'parse_args', return_value=args), \
                 patch.object(outbox, 'run', side_effect=failure), \
                 patch.object(outbox, 'runtime_report', return_value={}), \
                 contextlib.redirect_stdout(output):
                self.assertEqual(outbox.main(), 1)
            report = json.loads(output.getvalue())
            self.assertFalse(report['passed'])
            self.assertEqual(report['failure_code'], failure.code)
            self.assertEqual(report['failure_diagnostic'], failure.diagnostic())
            self.assertNotIn(SECRET, output.getvalue())

    def test_real_compatibility_projection_reproduces_nine_field_failure(self):
        # cli/src/client2_host.rs defaults to the CLI listener's old Client2 view.
        # Runtime dev.6's rpc_serve::health_body supplies the modern flat view.
        modern = copy.deepcopy(self.health)
        host_image = self.root / 'cli-host'
        host_image.write_bytes(b'not the runtime image')
        legacy = {key: modern[key] for key in ('v', 'data_dir', 'installation_root')}
        legacy.update(server='respire', bin='cli-version', pid=123, exe=str(host_image),
                      compatibility_host='client2-v0256', backend_pid=456,
                      backend_instance_id=modern['instance_id'],
                      backend_process_start_id=modern['process_start_id'])
        self.owner.exe = lambda: str(host_image)
        self.health = legacy
        with self.assertRaises(native.RuntimeHealthFailure) as caught:
            self.verify()
        self.assertEqual(list(caught.exception.fields), [
            'selected_image', 'image_path', 'process_start_id', 'runtime_version',
            'bin_version', 'installation_id', 'account_id', 'instance_id', 'generation'])
        self.assertEqual(self.args.runtime_identity_receipts, [])
        self.owner.exe = lambda: str(self.image)
        self.health = modern
        self.assertEqual(self.verify()['image_sha256'], self.args.runtime_sha256)

    def test_runtime_http_selects_only_health_representation(self):
        import io
        from unittest.mock import Mock
        smoke = runtime.Smoke.__new__(runtime.Smoke)
        smoke.opener = Mock()
        for method, path in [('GET', '/api/health'), ('POST', '/api/rpc'), ('GET', '/api/self')]:
            response = io.BytesIO(json.dumps(self.health).encode())
            response.code, response.headers = 200, {}
            smoke.opener.open.return_value = response
            self.assertEqual(smoke.http('http://127.0.0.1:1', method, path)[1], self.health)
            request = smoke.opener.open.call_args.args[0]
            self.assertEqual(request.get_header('X-respire-health'),
                             'runtime-v1' if path == '/api/health' else None)
            self.assertEqual(smoke.opener.open.call_args.kwargs['timeout'], 90)

        smoke.args, smoke.root, smoke.library = self.args, self.root, self.profile
        smoke.env, smoke.port, smoke.url = {}, 1234, 'http://127.0.0.1:1234'
        (self.root / 'runtime').mkdir()
        (self.root / 'runtime/endpoint.json').write_text('{}')
        token = self.root / 'runtime/token'
        child = Mock(pid=123)
        child.poll.return_value = None
        # Cover first boot, restart with the host token, and the explicit Off state.
        for existing_token, unlock in ((False, True), (True, True), (True, False)):
            with self.subTest(existing_token=existing_token, unlock=unlock):
                token.unlink(missing_ok=True)
                if existing_token:
                    token.write_text(SECRET)
                smoke.child = None
                waiting = dict(self.health, startup_complete=False, store_ready=False)
                ready = dict(self.health, startup_complete=True, store_ready=False)
                unlocked = dict(ready, store_ready=True)
                health = [waiting, ready, unlocked] if unlock else [waiting, ready]
                events = []
                def direct(args, **kwargs):
                    events.append(tuple(args))
                    if args == ['runtime', 'unlock']:
                        self.assertIn('identity', events)
                        token.write_text(SECRET)
                        return {'summary': {'store_ready': True}}
                with patch.object(runtime.subprocess, 'Popen', return_value=child) as launched, \
                     patch.object(runtime.time, 'sleep'), \
                     patch.object(smoke, 'direct', side_effect=direct) as executed, \
                     patch.object(smoke, 'http', side_effect=[(200, value, {}) for value in health]), \
                     patch.object(runtime, 'verify_runtime_health', side_effect=lambda *a: events.append('identity')):
                    smoke.start(unlock=unlock)
                self.assertEqual(launched.call_args.args[0],
                                 [str(self.image), 'serve', '--port', '1234', '--host', '127.0.0.1'])
                self.assertEqual(sum(call.args[0] == ['runtime', 'unlock']
                                     for call in executed.call_args_list), int(unlock))
                self.assertEqual(events.count('identity'), len(health))
        smoke.child = None
        with patch.object(runtime.subprocess, 'Popen', return_value=child), \
             patch.object(smoke, 'direct') as executed, \
             patch.object(smoke, 'http', return_value=(200, ready, {})), \
             patch.object(runtime, 'verify_runtime_health', side_effect=native.RuntimeHealthFailure(
                 'runtime_health_fields_mismatch', ['pid'])):
            with self.assertRaises(native.RuntimeHealthFailure):
                smoke.start()
        self.assertEqual(executed.call_count, 1)  # Stop only; no key delivery to a wrong owner.
        for failure in ('unlock_receipt', 'store_locked', 'token_changed'):
            smoke.child = None
            token.write_text(SECRET)
            def launch(*args, **kwargs):
                if failure == 'token_changed':
                    token.write_text('changed')
                return child
            with self.subTest(failure=failure), \
                 patch.object(runtime.subprocess, 'Popen', side_effect=launch), \
                 patch.object(smoke, 'direct', return_value={'summary': {
                     'store_ready': failure != 'unlock_receipt'}}) as executed, \
                 patch.object(smoke, 'http', return_value=(200, ready, {})), \
                 patch.object(runtime, 'verify_runtime_health'):
                with self.assertRaises(runtime.Failure):
                    smoke.start()
                self.assertEqual(sum(call.args[0] == ['runtime', 'unlock']
                                     for call in executed.call_args_list), int(failure != 'token_changed'))
        for off in (True, False):
            with patch.object(smoke, 'stop'), patch.object(smoke, 'start') as started, \
                 patch.object(smoke, 'direct', return_value={'summary': {'memory_off': off}}):
                smoke.agent_config(['--set', 'memory_off=' + str(off).lower()])
                started.assert_called_once_with(unlock=not off)

    def test_outbox_health_selectors_and_scoped_receipt_checks(self):
        import io
        from unittest.mock import Mock, MagicMock
        spec = importlib.util.spec_from_file_location('outbox_selector', Path(__file__).with_name('dev-outbox-smoke.py'))
        outbox = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(outbox)
        fixture = outbox.Fixture.__new__(outbox.Fixture)
        fixture.args = types.SimpleNamespace(binary=self.image, runtime_binary=self.image)
        fixture.a = {'RSRS_DATA_DIR': str(self.root), 'RSRS_RUNTIME_BIN': str(self.image), 'RSRS_RPC_PORT': '1234'}
        fixture.direct_failures, fixture.port = [], 1234
        self.health['startup_complete'] = True
        fixture.child = Mock(pid=123)
        (self.root / 'runtime').mkdir()
        (self.root / 'runtime' / 'endpoint.json').write_text('{}')
        requests = []
        wrong_receipt = False
        def response(request, **kwargs):
            requests.append(request)
            if request.full_url.endswith('/api/health'):
                self.assertEqual(request.get_header('X-respire-health'), 'runtime-v1')
                self.assertEqual(kwargs['timeout'], 5)
                value = self.health
            else:
                body = json.loads(request.data)
                value = {key: body[key] for key in ('v', 'id', 'operation_id', 'idempotency_key', 'scope')}
                value.update(ok=True, exit=0)
                if wrong_receipt:
                    value['scope'] = dict(value['scope'], instance_id='wrong-instance')
            stream = io.BytesIO(json.dumps(value).encode())
            stream.status = 200
            return stream
        def wait(action, seconds, code):
            self.assertTrue(action())
        fake_socket = MagicMock()
        fake_socket.__enter__.return_value.getsockname.return_value = ('127.0.0.1', 1234)
        child = Mock(pid=123)
        child.poll.return_value = None
        with patch.object(outbox.urllib.request, 'urlopen', side_effect=response), \
             patch.object(outbox, 'verify_runtime_health') as verified, \
             patch.object(outbox.subprocess, 'run', return_value=types.SimpleNamespace(returncode=0,
                 stdout=b'{"errors":[],"summary":{"store_ready":true}}')) as executed, \
             patch.object(outbox.subprocess, 'Popen', return_value=child), \
             patch.object(outbox.socket, 'socket', return_value=fake_socket), \
             patch.object(outbox, 'wait_for', side_effect=wait):
            fixture.direct(fixture.a, ['sync'])
            fixture.start()
            self.assertTrue(fixture.rpc(['status'])['ok'])
            self.assertEqual(verified.call_count, 4)  # direct, ready, start-status, explicit status
            self.assertEqual(sum(call.args[0][-2:] == ['runtime', 'unlock']
                                 for call in executed.call_args_list), 1)
            wrong_receipt = True
            with self.assertRaisesRegex(RuntimeError, '^local_rpc_failed$'):
                fixture.rpc(['status'])
            verified.side_effect = native.RuntimeHealthFailure('runtime_health_fields_mismatch', ['selected_image'])
            before = len(requests)
            with self.assertRaises(native.RuntimeHealthFailure):
                fixture.rpc(['remember', 'must-not-replay'])
            self.assertEqual(len(requests), before + 1)  # Health only; no business RPC.
        # The header neither bypasses verification nor retries a failed write.
        self.assertEqual(len([r for r in requests if r.full_url.endswith('/api/rpc')]), 3)

    def test_source_selector_contract_is_the_product_contract(self):
        root = Path(__file__).resolve().parent.parent
        host = (root / 'cli/src/client2_host.rs').read_text()
        transport = (root / 'crates/commands/src/net_rpc.rs').read_text()
        self.assertIn('name.eq_ignore_ascii_case("X-Respire-Health") && value == "runtime-v1"', host)
        self.assertIn('let response = if modern { live } else {', host)
        self.assertIn('.set("X-Respire-Health", "runtime-v1")', transport)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.profile = self.root / 'profile'
        self.profile.mkdir()
        self.image = self.root / 'image'
        self.image.write_bytes(b'fixture bytes, not an executable')
        digest = native.hashlib.sha256(self.image.read_bytes()).hexdigest()
        self.args = types.SimpleNamespace(runtime_version='fixture', runtime_binary=self.image, runtime_sha256=digest, runtime_identity_receipts=[])
        self.owner = types.SimpleNamespace(pid=123, create_time=lambda: 1, exe=lambda: str(self.image))
        install, account = native.runtime_scope_ids(self.root, self.profile, {})
        self.health = dict(v=1, pid=123, exe=str(self.image), image_path=str(self.image), process_start_id='birth', runtime_version='fixture', bin='fixture', installation_root=str(self.root), installation_id=install, data_dir=str(self.profile), account_id=account, instance_id='instance', generation=1, image_sha256=digest)
        self.enterContext(patch.dict(sys.modules, {'psutil': types.SimpleNamespace(Process=lambda pid: self.owner)}))
        self.enterContext(patch.object(native, 'process_start_id', return_value='birth'))
        self.enterContext(patch.object(native.sys, 'platform', 'win32' if os.name == 'nt' else 'fixture'))
        self.enterContext(patch.dict(os.environ, {}, clear=True))

    def verify(self):
        return native.verify_runtime_health(self.args, self.health, self.root, self.profile, 123)

    def test_success_receipts_and_cached_success(self):
        first = self.verify()
        self.assertEqual(self.verify(), first)
        self.assertEqual(len(self.args.runtime_identity_receipts), 1)
        self.assertEqual(first['image_sha256'], self.args.runtime_sha256)

    def test_all_health_fields_fail_closed(self):
        keys = dict(protocol='v', exe='exe', image_path='image_path', process_start_id='process_start_id', runtime_version='runtime_version', bin_version='bin', installation_root='installation_root', installation_id='installation_id', profile='data_dir', account_id='account_id', instance_id='instance_id', generation='generation')
        original = copy.deepcopy(self.health)
        for field, key in keys.items():
            with self.subTest(field=field):
                self.health = copy.deepcopy(original)
                self.health[key] = '' if key == 'instance_id' else SECRET
                with self.assertRaises(native.RuntimeHealthFailure) as caught:
                    self.verify()
                self.assertEqual(caught.exception.code, 'runtime_health_fields_mismatch')
                self.assertIn(field, caught.exception.fields)
                self.assertNotIn(SECRET, json.dumps(caught.exception.diagnostic()))
                self.assertEqual(self.args.runtime_identity_receipts, [])
        self.health = original
        self.owner.pid = 456
        with self.assertRaises(native.RuntimeHealthFailure) as caught:
            self.verify()
        self.assertIn('pid', caught.exception.fields)
        self.owner.pid = 123
        self.args.runtime_binary = self.root / SECRET
        with self.assertRaises(native.RuntimeHealthFailure) as caught:
            self.verify()
        self.assertIn('selected_image', caught.exception.fields)

    def test_ownership_and_profile_still_fail(self):
        if os.name == 'posix':
            self.root.chmod(0o755)
            with self.assertRaisesRegex(native.RuntimeHealthFailure, 'runtime_health_installation_not_private_owned'):
                self.verify()
            self.root.chmod(0o700)
        self.profile = self.root.parent
        with self.assertRaisesRegex(native.RuntimeHealthFailure, 'runtime_health_profile_escape'):
            self.verify()

    def test_digest_and_cached_file_change_still_fail(self):
        self.health['image_sha256'] = SECRET
        with self.assertRaisesRegex(native.RuntimeHealthFailure, 'runtime_health_digest_mismatch'):
            self.verify()
        self.health['image_sha256'] = self.args.runtime_sha256
        self.verify()
        self.image.write_bytes(b'changed')
        with self.assertRaisesRegex(native.RuntimeHealthFailure, 'runtime_health_disk_image_changed'):
            self.verify()

    def test_inspection_races_still_fail(self):
        real_stat = self.image.stat()
        fake_stat = types.SimpleNamespace(st_dev=-1, st_ino=0, st_size=0, st_mtime_ns=0, st_ctime_ns=0,
                                         st_birthtime_ns=0)
        with patch.object(native.os, 'fstat', return_value=fake_stat):
            with self.assertRaisesRegex(native.RuntimeHealthFailure, 'runtime_health_os_disk_image_mismatch'):
                self.verify()
        with patch.object(native.os, 'fstat', side_effect=[real_stat, fake_stat]):
            with self.assertRaisesRegex(native.RuntimeHealthFailure, 'runtime_health_image_changed_during_inspection'):
                self.verify()
        with patch.object(native, 'process_start_id', side_effect=['birth', SECRET]):
            with self.assertRaisesRegex(native.RuntimeHealthFailure, 'runtime_health_os_identity_changed'):
                self.verify()
        self.assertEqual(self.args.runtime_identity_receipts, [])


if __name__ == '__main__':
    unittest.main()
