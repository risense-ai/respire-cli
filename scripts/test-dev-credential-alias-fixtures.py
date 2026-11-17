#!/usr/bin/env python3
"""Offline fixture regressions; no native credential store or network access."""
import ast
from contextlib import closing, nullcontext
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.dont_write_bytecode = True
HERE = Path(__file__).parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


native = load('credential_test_native', 'dev-migration-keyring.py')
secret_service = load('credential_test_service', 'dev-migration-secret-service.py')
profile = load('credential_test_profile', 'dev-profile-migration-smoke.py')
legacy = profile.support
USER = 'ci-migrate-' + '1' * 16
ALIAS = 'login-' + '2' * 32
OTHER = 'login-' + '3' * 32
PASSWORD = 'synthetic-password-never-report'
SUPER = 'synthetic-super-never-report'


class KeylessRuntimeIdentityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.profile = Path(temporary.name)
        self.runtime = self.profile / 'rsrs-runtime.exe'
        self.runtime.touch()
        self.other = self.profile / 'other'
        self.other.mkdir()
        (self.other / self.runtime.name).touch()
        self.metadata = dict(runtime_version='2.0.0-dev.22', binary_sha256='a' * 64)
        self.health = dict(v=1, pid=123, runtime_version=self.metadata['runtime_version'],
            image_sha256=self.metadata['binary_sha256'], image_path=str(self.runtime),
            installation_root=str(self.profile), data_dir=str(self.profile))
        tree = ast.parse((HERE / 'dev-profile-migration-smoke.py').read_text())
        assertion = next(node for node in ast.walk(tree) if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name) and node.func.id == 'require'
            and len(node.args) == 2 and isinstance(node.args[1], ast.Constant)
            and node.args[1].value == 'keyless_runtime_identity_mismatch')
        self.assertion = compile(ast.Expression(assertion), '<keyless-runtime-identity>', 'eval')

    def verify(self):
        eval(self.assertion, dict(require=profile.require, health=self.health,
            child=SimpleNamespace(pid=123), metadata=self.metadata, runtime=self.runtime,
            profile=self.profile.resolve(), keyring_backend=native, sys=sys, Path=Path))

    def test_exact_identity_passes(self):
        self.verify()
        smoke = object.__new__(profile.Smoke)
        smoke.args = SimpleNamespace(binary=self.runtime)
        installation = self.profile / '.rsrs'
        destination = installation / 'accounts' / 'first'
        sibling = installation / 'accounts' / 'second'
        destination.mkdir(parents=True)
        sibling.mkdir()
        session = dict(user=USER, keyring_account=ALIAS, token='fixture-session')
        (destination / 'session.json').write_text(json.dumps(session), encoding='utf-8')
        (sibling / 'session.json').write_text(json.dumps(dict(session, user='other')), encoding='utf-8')
        config = destination / 'client.json'
        original = (json.dumps({'data_dir': str(sibling), 'addr': legacy.UPSTREAM}) + '\n').encode()
        default = {'HOME': str(self.profile)}
        for contents in (original, None):
            for fails in (False, True):
                with self.subTest(config_present=contents is not None, fails=fails):
                    if contents is not None:
                        config.write_bytes(contents)
                    with patch.object(legacy, 'install_published_runtime'):
                        with self.assertRaisesRegex(RuntimeError, '^fixture-check-failed$') if fails else nullcontext():
                            with smoke.selected_profile(default, {'destination': destination}) as env:
                                self.assertEqual(smoke.session(env), session)
                                self.assertTrue(smoke.profile(env).samefile(destination))
                                if fails:
                                    raise RuntimeError('fixture-check-failed')
                    self.assertEqual(config.read_bytes() if config.exists() else None, contents)
                    config.unlink(missing_ok=True)
        outside = json.dumps({'data_dir': str(self.other)}).encode()
        config.write_bytes(outside)
        with patch.object(legacy, 'install_published_runtime') as install:
            with self.assertRaisesRegex(RuntimeError, '^login_profile_selection_outside_fixture$'):
                with smoke.selected_profile(default, {'destination': destination}):
                    self.fail('external selection accepted')
            install.assert_not_called()
        self.assertEqual(config.read_bytes(), outside)

    @unittest.skipUnless(sys.platform == 'win32', 'Windows final-path identity')
    def test_windows_extended_path_and_case_use_full_file_identity(self):
        for path in ('\\\\?\\' + str(self.runtime),
                     ('\\\\?\\' + str(self.runtime)).upper().replace('\\', '/')):
            with self.subTest(path_form=path[:7]):
                self.health['image_path'] = path
                self.verify()

        smoke = object.__new__(profile.Smoke)
        root = self.profile / 'owned'
        child = root / 'accounts' / 'fixture-account'
        child.mkdir(parents=True)
        outside = self.profile / 'owned-other'
        outside.mkdir()
        env = {'RSRS_DATA_DIR': str(root)}
        config = root / 'client.json'
        session = dict(user=USER, token='synthetic-session')
        for target in (root, child):
            (target / 'session.json').write_text(json.dumps(session), encoding='utf-8')
            for selected in (str(target), '\\\\?\\' + str(target),
                             ('\\\\?\\' + str(target)).upper().replace('\\', '/')):
                with self.subTest(selected=selected):
                    config.write_text(json.dumps({'data_dir': selected}), encoding='utf-8')
                    self.assertTrue(smoke.profile(env).samefile(target))
                    self.assertEqual(smoke.session(env), session)
        for target in (self.profile, outside):
            for selected in (str(target), '\\\\?\\' + str(target)):
                with self.subTest(outside=selected):
                    config.write_text(json.dumps({'data_dir': selected}), encoding='utf-8')
                    with self.assertRaisesRegex(RuntimeError, '^login_profile_selection_outside_fixture$'):
                        smoke.session(env)
        for selected in ('', None):
            config.write_text(json.dumps({'data_dir': selected}), encoding='utf-8')
            with self.assertRaisesRegex(RuntimeError, '^login_profile_selection_invalid$'):
                smoke.session(env)
        config.write_text('{', encoding='utf-8')
        with self.assertRaises(json.JSONDecodeError):
            smoke.session(env)

    def test_every_identity_field_remains_strict(self):
        for field, value in dict(v=2, pid=456, runtime_version='2.0.0-dev.21',
                image_sha256='b' * 64, image_path=str(self.other / self.runtime.name),
                installation_root=str(self.other), data_dir=str(self.other)).items():
            with self.subTest(field=field):
                original = self.health[field]
                self.health[field] = value
                with self.assertRaisesRegex(RuntimeError, '^keyless_runtime_identity_mismatch$'):
                    self.verify()
                self.health[field] = original


class RestartRetainedCredentialTests(unittest.TestCase):
    def test_both_restart_checks_use_platform_consumer_and_preserve_alias(self):
        tree = ast.parse((HERE / 'dev-profile-migration-smoke.py').read_text())
        restart = next(node for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name == 'restart_key_handoff')
        checks = [node for node in restart.body if isinstance(node, ast.If)
            and ast.unparse(node.test) == "sys.platform == 'darwin'"]
        self.assertEqual(len(checks), 2)
        env, fixture = {'RSRS_DATA_DIR': 'owned-profile'}, {'alias': ALIAS}
        for index, check in enumerate(checks):
            for platform in ('darwin', 'win32', 'linux'):
                for alias in (ALIAS, OTHER):
                    with self.subTest(check=index, platform=platform, original_alias=alias == ALIAS):
                        session = {'keyring_account': alias}
                        smoke = SimpleNamespace(session=lambda env: session,
                            verify_mac_native_credentials=Mock(), verify_retained_current_credentials=Mock())
                        code = compile(ast.Module(body=[check], type_ignores=[]), '<restart-retained>', 'exec')
                        namespace = dict(self=smoke, env=env, fixture=fixture,
                            require=profile.require, sys=SimpleNamespace(platform=platform))
                        if platform == 'darwin' and alias != ALIAS:
                            with self.assertRaisesRegex(RuntimeError, '^existing_target_credential_identity_changed$'):
                                exec(code, namespace)
                            smoke.verify_mac_native_credentials.assert_not_called()
                            smoke.verify_retained_current_credentials.assert_not_called()
                        else:
                            exec(code, namespace)
                            if platform == 'darwin':
                                smoke.verify_mac_native_credentials.assert_called_once_with(env, fixture)
                                smoke.verify_retained_current_credentials.assert_not_called()
                            else:
                                smoke.verify_retained_current_credentials.assert_called_once_with(session, fixture)
                                smoke.verify_mac_native_credentials.assert_not_called()


class MemoryKeys(native.TrackedKeys):
    credential_backend = 'native'
    def __init__(self):
        super().__init__(Path('unused'))
        self.values = {}
        self.reads = []

    def _read(self, service, slot):
        self.reads.append((service, slot))
        return self.values.get((service, slot))

    def _put(self, service, slot, value):
        self.values[service, slot] = value

    def _remove(self, service, slot):
        self.values.pop((service, slot), None)

    def created(self, alias, super_password=SUPER):
        if super_password is not None:
            self.values['rsrs', 'super:' + alias] = super_password
        self.values['rsrs', 'pass:' + alias] = PASSWORD


class AliasTests(unittest.TestCase):
    def setUp(self):
        self.keys = MemoryKeys()
        self.session = dict(user=USER, keyring_account=ALIAS, keyring_backend='native')
        self.fixture = dict(account={'user': USER}, alias=ALIAS, code=SUPER, password=PASSWORD)
        self.smoke = object.__new__(profile.Smoke)
        self.smoke.keys = self.keys
        self.keys.created(ALIAS)
        self.keys.track_created_login(self.session, USER, SUPER, PASSWORD)

    def test_current_target_uses_original_alias_not_username(self):
        self.keys.reads.clear()
        self.smoke.verify_retained_current_credentials(self.session, self.fixture)
        self.assertEqual(self.keys.reads, [('rsrs', 'super:' + ALIAS), ('rsrs', 'pass:' + ALIAS)])

    def test_foreign_user_alias_missing_alias_rejected_before_read(self):
        for change in ({'user': 'foreign'}, {'keyring_account': OTHER}, {'keyring_account': None}):
            with self.subTest(change=list(change)):
                self.keys.reads.clear()
                with self.assertRaisesRegex(RuntimeError, '^existing_target_credential_identity_changed$'):
                    self.smoke.verify_retained_current_credentials(dict(self.session, **change), self.fixture)
                self.assertFalse(self.keys.reads)

    def test_unowned_alias_rejected(self):
        self.keys.entries.clear()
        with self.assertRaisesRegex(RuntimeError, '^credential_not_owned_by_fixture$'):
            self.smoke.verify_retained_current_credentials(self.session, self.fixture)

    def test_wrong_or_missing_credential_not_hidden(self):
        for value in ('wrong', None):
            self.keys.values['rsrs', 'pass:' + ALIAS] = value
            with self.assertRaises(RuntimeError):
                self.smoke.verify_retained_current_credentials(self.session, self.fixture)

    def test_tracking_rejects_foreign_user_and_invalid_alias(self):
        for session in ({'user': 'foreign', 'keyring_account': OTHER}, {'user': USER},
                        {'user': USER, 'keyring_account': 'foreign'}):
            keys = MemoryKeys()
            with self.assertRaises(RuntimeError):
                keys.track_created_login(session, USER, SUPER, PASSWORD)
            self.assertFalse(keys.entries)
            self.assertFalse(keys.reads)

    def test_wrong_password_tracked_for_cleanup_without_secret_output(self):
        keys = MemoryKeys()
        keys.created(OTHER, None)
        with self.assertRaisesRegex(RuntimeError, '^login_credential_fixture_value_changed$') as raised:
            keys.track_created_login(dict(user=USER, keyring_account=OTHER), USER, None, 'wrong')
        report = keys.cleanup()
        self.assertTrue(report['passed'])
        self.assertFalse(keys.values)
        for forbidden in (PASSWORD, SUPER, OTHER, USER):
            self.assertNotIn(forbidden, str(raised.exception) + json.dumps(report))

    def test_tty_password_login_versions_track_before_return(self):
        for version in (1, 2):
            with self.subTest(version=version):
                keys = MemoryKeys()
                smoke = object.__new__(legacy.Smoke)
                smoke.keys = keys
                aliases = iter((ALIAS, OTHER))
                current = {}
                def cli(env, *args, **kwargs):
                    prompts = kwargs['prompts']
                    self.assertEqual(prompts[-1][1] == 'n', not bool(current.get('token')))
                    if not current.get('token'):
                        prompt = prompts[-1][0].lstrip()
                        self.assertIn('"' + prompt + '"', (HERE.parent / 'cli/src/login.rs').read_text(encoding='utf-8'))
                    alias = next(aliases)
                    keys.created(alias, None if version == 1 else SUPER)
                    current.update(user=USER, keyring_account=alias, token="synthetic-token", vault_version=version)
                    if version in (1, 3):
                        current['legacy_secret_backend'] = 'native'
                        keys.values['rsrs', 'legacy-secret:' + alias] = 'synthetic-factor'
                    return {'summary': {'ok': True}}
                smoke.cli = cli
                smoke.session = lambda env: current
                for env in ({}, {'RSRS_PASS': PASSWORD}):
                    smoke.password_login(env, USER, PASSWORD, version, SUPER)
                    self.assertIn(('rsrs', 'pass:' + current['keyring_account']), keys.entries)
                self.assertEqual(len(keys.entries), 6 if version == 3 else 4)
                self.assertTrue(keys.cleanup()['passed'])
                self.assertFalse(keys.values)

    def test_interactive_factor_env_is_removed_only_from_login_copy(self):
        for version in (1, 2):
            keys = MemoryKeys()
            smoke = object.__new__(legacy.Smoke)
            smoke.keys = keys
            current = {'user': USER}
            env = {'RSRS_SUPER': SUPER, 'RSRS_DATA_DIR': 'owned', 'RSRS_PASS': PASSWORD}
            before = dict(env)
            def cli(child_env, *args, **kwargs):
                self.assertIsNot(child_env, env)
                self.assertEqual(child_env.get('RSRS_SUPER'), SUPER if version == 1 else None)
                prompts = kwargs['prompts']
                self.assertEqual(prompts[1], ('  login password: ', PASSWORD))
                self.assertEqual(len(prompts), 3 if version == 1 else 4)
                self.assertEqual(prompts[-1], ('  Merge selected local memories into this server account (skip identical bodies; keep existing records)? [y/N]: ', 'n'))
                if version != 1:
                    self.assertEqual(prompts[2], ('  super password (A3-…): ', SUPER))
                self.assertNotIn(SUPER, args)
                self.assertNotIn(PASSWORD, args)
                keys.created(ALIAS, None if version == 1 else SUPER)
                current.update(keyring_account=ALIAS, token='synthetic-token', vault_version=version)
                if version in (1, 3):
                    current['legacy_secret_backend'] = 'native'
                    keys.values['rsrs', 'legacy-secret:' + ALIAS] = 'synthetic-factor'
                return {'summary': {}}
            smoke.cli = cli
            smoke.session = lambda env: dict(current)
            smoke.password_login(env, USER, PASSWORD, version, SUPER)
            self.assertEqual(env, before)
            self.assertTrue(keys.cleanup()['passed'])
            self.assertFalse(keys.values)

    def test_v1_fresh_login_blocks_use_hidden_factor_without_a_seeded_session(self):
        tree = ast.parse((HERE / 'dev-legacy-vault-smoke.py').read_text(encoding='utf-8'))
        run = next(node for node in ast.walk(tree)
                   if isinstance(node, ast.FunctionDef) and node.name == 'run_version')
        for variable in ('old_login_env', 'final_env'):
            start = next(index for index, node in enumerate(run.body)
                         if isinstance(node, ast.Assign)
                         and any(isinstance(target, ast.Name) and target.id == variable for target in node.targets))
            end = next(index for index, node in enumerate(run.body[start:], start)
                       if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
                       and isinstance(node.value.func, ast.Attribute) and node.value.func.attr == 'password_login')
            code = compile(ast.Module(body=run.body[start:end + 1], type_ignores=[]),
                           '<actual-v1-login-setup>', 'exec')
            for fails in (False, True):
                with self.subTest(profile=variable, fails=fails), tempfile.TemporaryDirectory() as temp:
                    smoke = object.__new__(legacy.Smoke)
                    smoke.root, smoke.model = Path(temp), Path(temp) / 'models'
                    smoke.base_env, smoke.report = {}, {}
                    smoke.args = SimpleNamespace(binary=Path('fixture-cli'))
                    smoke.save = Mock()
                    keys = MemoryKeys()
                    keys.configure_env = Mock()
                    smoke.keys = keys
                    factor = 'fixture-account-secret'

                    def cli(env, *args, **kwargs):
                        self.assertFalse((Path(env['RSRS_DATA_DIR']) / 'session.json').exists())
                        self.assertEqual(kwargs['prompts'][-2], ('  original v1 Account Secret: ', factor))
                        self.assertEqual(kwargs['prompts'][-1][1], 'n')
                        self.assertNotIn(factor, args)
                        if fails:
                            raise RuntimeError('auth_failed')
                        keys.created(ALIAS, None)
                        keys.values['rsrs', 'legacy-secret:' + ALIAS] = factor
                        target = Path(env['RSRS_DATA_DIR']) / 'accounts' / 'fixture-account'
                        target.mkdir(parents=True)
                        (Path(env['RSRS_DATA_DIR']) / 'client.json').write_text(
                            json.dumps({'data_dir': str(target)}), encoding='utf-8')
                        smoke.write_session(dict(env, RSRS_DATA_DIR=str(target)), dict(user=USER,
                            keyring_account=ALIAS, token='fixture-token', vault_version=1,
                            keyring_backend='native', legacy_secret_backend='native'))
                        return {'summary': {'ok': True, 'dir': str(target)}}

                    smoke.cli = cli
                    scope = dict(self=smoke, version=1, user=USER, password=PASSWORD,
                                 original_super=factor, secret=factor)
                    with patch.object(legacy, 'install_published_runtime'):
                        if fails:
                            with self.assertRaisesRegex(RuntimeError, '^auth_failed$'):
                                exec(code, scope)
                            self.assertFalse(keys.entries)
                        else:
                            exec(code, scope)
                            self.assertEqual(keys.entries, {('rsrs', 'pass:' + ALIAS), ('rsrs', 'legacy-secret:' + ALIAS)})
                    self.assertTrue(keys.cleanup()['passed'])
                    self.assertFalse(keys.values)
                    root = Path(scope[variable]['RSRS_DATA_DIR'])
                    session_path = smoke.profile(scope[variable]) / 'session.json'
                    if not fails:
                        self.assertNotEqual(session_path.parent, root)
                        self.assertFalse((root / 'session.json').exists())
                    session_path.write_text('{', encoding='utf-8')
                    with self.assertRaises(json.JSONDecodeError):
                        smoke.session(scope[variable])
                    config_path = root / 'client.json'
                    for selected, failure_code in ((str(root.parent), 'login_profile_selection_outside_fixture'),
                                                   ('', 'login_profile_selection_invalid'),
                                                   (None, 'login_profile_selection_invalid')):
                        config_path.write_text(json.dumps({'data_dir': selected}), encoding='utf-8')
                        with self.assertRaisesRegex(RuntimeError, '^' + failure_code + '$'):
                            smoke.session(scope[variable])
                    config_path.write_text('{', encoding='utf-8')
                    with self.assertRaises(json.JSONDecodeError):
                        smoke.session(scope[variable])

    def test_v3_fresh_login_blocks_use_stdin_rpc_and_keep_failures_fatal(self):
        tree = ast.parse((HERE / 'dev-legacy-vault-smoke.py').read_text(encoding='utf-8'))
        run = next(node for node in ast.walk(tree)
                   if isinstance(node, ast.FunctionDef) and node.name == 'run_version')
        for variable in ('old_login_env', 'final_env'):
            start = next(index for index, node in enumerate(run.body)
                         if isinstance(node, ast.Assign)
                         and any(isinstance(target, ast.Name) and target.id == variable for target in node.targets))
            end = next(index for index, node in enumerate(run.body[start:], start)
                       if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
                       and isinstance(node.value.func, ast.Attribute) and node.value.func.attr == 'password_login')
            code = compile(ast.Module(body=run.body[start:end + 1], type_ignores=[]),
                           '<actual-v3-login-setup>', 'exec')
            failures = dict(auth='cli_failed_login', pending='cli_failed_login',
                transport='legacy_login_rpc_transport_mismatch', wire_version='legacy_login_rpc_transport_mismatch',
                wire_exit='legacy_login_rpc_transport_mismatch', wire_ok='legacy_login_rpc_transport_mismatch',
                transaction='legacy_login_rpc_transaction_mismatch', operation='legacy_login_rpc_transaction_mismatch',
                outcome='legacy_login_rpc_transaction_mismatch', identity='legacy_login_rpc_identity_mismatch',
                required_inputs='legacy_login_rpc_identity_mismatch', status='legacy_login_rpc_not_committed',
                errors='cli_error_login', stop='owned_runtime_stop_failed', json='invalid_cli_json_login')
            for failure in (None, *failures):
                with self.subTest(profile=variable, failure=failure), tempfile.TemporaryDirectory() as temp:
                    smoke = object.__new__(legacy.Smoke)
                    smoke.root, smoke.model = Path(temp), Path(temp) / 'models'
                    smoke.base_env, smoke.report, smoke.diagnostic_secrets = {}, {}, {PASSWORD, SUPER, 'fixture-secret-key'}
                    smoke.args = SimpleNamespace(binary=Path('fixture-cli'))
                    smoke.save = Mock()
                    keys = MemoryKeys()
                    keys.configure_env = Mock()
                    smoke.keys = keys
                    requests, stops = [], []
                    factor = 'fixture-secret-key'
                    committed = failure not in ('auth', 'pending')

                    def child(argv, **kwargs):
                        env = kwargs['env']
                        if '--stop' in argv:
                            stops.append(argv)
                            return SimpleNamespace(returncode=1 if failure == 'stop' else 0)
                        self.assertEqual(argv, ['fixture-cli', '--json', '--host-rpc-stdio'])
                        self.assertNotIn('RSRS_SUPER', env)
                        self.assertFalse((Path(env['RSRS_DATA_DIR']) / 'session.json').exists())
                        request = json.loads(kwargs['input'])
                        requests.append(request)
                        self.assertEqual(request['v'], 1)
                        self.assertEqual(request['method'], 'auth.login')
                        self.assertEqual(request['params'], dict(addr=legacy.UPSTREAM, user=USER,
                            password=PASSWORD, super=SUPER, continuation=json.dumps({'secret_key': factor})))
                        self.assertNotIn(factor, str(argv))
                        self.assertNotIn(PASSWORD, str(argv))
                        self.assertNotIn(SUPER, str(argv))
                        operation = '12345678-1234-4234-8234-123456789abc'
                        self.assertNotEqual(request['id'], operation)
                        receipt = dict(operation_id=operation, outcome='committed',
                            source_profile=str(Path(env['RSRS_DATA_DIR']).resolve()),
                            login=dict(user=USER, addr=legacy.UPSTREAM, required_inputs=[]))
                        envelope = dict(status='ok', summary=receipt, errors=[])
                        if committed:
                            keys.created(ALIAS)
                            keys.values['rsrs', 'legacy-secret:' + ALIAS] = factor
                            target = Path(env['RSRS_DATA_DIR']) / 'accounts' / 'fixture-account'
                            target.mkdir(parents=True)
                            (Path(env['RSRS_DATA_DIR']) / 'client.json').write_text(
                                json.dumps({'data_dir': str(target)}), encoding='utf-8')
                            smoke.write_session(dict(env, RSRS_DATA_DIR=str(target)), dict(user=USER,
                                keyring_account=ALIAS, token='fixture-token', vault_version=3,
                                keyring_backend='native', legacy_secret_backend='native'))
                        exit_code = 1 if failure == 'auth' else 2 if failure == 'pending' else 0
                        if failure in ('auth', 'pending'):
                            envelope.update(status='fail' if failure == 'auth' else 'pending',
                                errors=[PASSWORD + SUPER + factor] if failure == 'auth' else [])
                            receipt['outcome'] = 'awaiting_input'
                        if failure == 'transaction':
                            receipt['source_profile'] = 'foreign-profile'
                        if failure == 'operation':
                            receipt['operation_id'] = request['id']
                        if failure == 'outcome':
                            receipt['outcome'] = 'awaiting_input'
                        if failure == 'identity':
                            receipt['login']['user'] = 'foreign-user'
                        if failure == 'required_inputs':
                            receipt['login']['required_inputs'] = ['secret_key']
                        if failure == 'status':
                            envelope['status'] = 'pending'
                        if failure == 'errors':
                            envelope['errors'] = [PASSWORD + SUPER + factor]
                        reply = dict(v=2 if failure == 'wire_version' else 1,
                            id='foreign' if failure == 'transport' else request['id'],
                            exit=1 if failure == 'wire_exit' else exit_code,
                            ok=False if failure == 'wire_ok' else exit_code == 0, envelope=envelope)
                        return SimpleNamespace(returncode=exit_code,
                            stdout=b'{' if failure == 'json' else json.dumps(reply).encode(), stderr=b'')

                    scope = dict(self=smoke, version=3, user=USER, password=PASSWORD,
                                 original_super=SUPER, secret=factor)
                    with patch.object(legacy, 'install_published_runtime'), \
                            patch.object(legacy.subprocess, 'run', side_effect=child), \
                            patch.object(legacy, 'run_hidden', side_effect=AssertionError('v3_must_use_stdin_rpc')):
                        if failure:
                            with self.assertRaisesRegex(RuntimeError, '^' + failures[failure] + '$') as raised:
                                exec(code, scope)
                            for forbidden in (PASSWORD, SUPER, factor):
                                self.assertNotIn(forbidden, str(raised.exception) + json.dumps(smoke.report))
                        else:
                            exec(code, scope)
                    self.assertEqual(len(requests), 1)
                    self.assertEqual(len(stops), 1)
                    self.assertEqual(keys.entries, {('rsrs', prefix + ALIAS) for prefix in
                        ('pass:', 'super:', 'legacy-secret:')} if committed else set())
                    self.assertEqual('RSRS_SUPER' in scope[variable], variable == 'final_env')
                    self.assertTrue(keys.cleanup()['passed'])
                    self.assertFalse(keys.values)

    def test_committed_session_tracked_even_when_post_auth_checks_fail(self):
        for reason in ('fixture_tty_missing_prompt', 'invalid_cli_json_login', 'owned_runtime_stop_failed'):
            with self.subTest(reason=reason), tempfile.TemporaryDirectory() as td:
                keys = MemoryKeys()
                smoke = object.__new__(legacy.Smoke)
                smoke.keys = keys
                root = Path(td)
                env = {'RSRS_DATA_DIR': str(root)}

                def cli(*args, **kwargs):
                    keys.created(ALIAS)
                    target = root / 'accounts' / 'fixture-account'
                    target.mkdir(parents=True)
                    (root / 'client.json').write_text(json.dumps({'data_dir': str(target)}), encoding='utf-8')
                    smoke.write_session(dict(env, RSRS_DATA_DIR=str(target)),
                        dict(user=USER, keyring_account=ALIAS, token='synthetic-token'))
                    raise RuntimeError(reason)

                smoke.cli = cli
                with self.assertRaisesRegex(RuntimeError, '^' + reason + '$'):
                    smoke.password_login(env, USER, PASSWORD, 2, SUPER)
                self.assertFalse((root / 'session.json').exists())
                self.assertEqual(keys.entries, {('rsrs', 'super:' + ALIAS), ('rsrs', 'pass:' + ALIAS)})
                report = keys.cleanup()
                self.assertTrue(report['passed'])
                self.assertFalse(keys.values)
                for secret in (PASSWORD, SUPER, ALIAS, USER):
                    self.assertNotIn(secret, json.dumps(report))

    def test_failed_login_does_not_claim_unchanged_alias_or_partial_session(self):
        for original, after in (({'user': USER, 'keyring_account': ALIAS, 'token': 'old'},
                                  {'user': USER, 'keyring_account': ALIAS, 'token': 'old'}),
                                 ({'user': USER}, {'user': USER, 'keyring_account': ALIAS})):
            keys = MemoryKeys()
            keys.created(ALIAS)
            smoke = object.__new__(legacy.Smoke)
            smoke.keys = keys
            current = dict(original)
            def cli(*args, **kwargs):
                current.clear(); current.update(after)
                raise RuntimeError('auth_failed')
            smoke.cli = cli
            smoke.session = lambda env: dict(current)
            with self.assertRaisesRegex(RuntimeError, '^auth_failed$'):
                smoke.password_login({}, USER, PASSWORD, 2, SUPER)
            self.assertFalse(keys.entries)
            self.assertFalse(keys.reads)
            self.assertTrue(keys.values)

    def test_success_without_new_session_is_rejected(self):
        smoke = object.__new__(legacy.Smoke)
        smoke.keys = MemoryKeys()
        smoke.session = lambda env: {'user': USER, 'keyring_account': ALIAS, 'token': 'old'}
        smoke.cli = lambda *args, **kwargs: {'summary': {}}
        with self.assertRaisesRegex(RuntimeError, '^login_credential_fixture_new_session_missing$'):
            smoke.password_login({}, USER, PASSWORD, 2, SUPER)
        self.assertFalse(smoke.keys.entries)

    def test_v1_migration_tracks_before_replacement_super_assertion_fails(self):
        # Execute the actual fixture block, including its assertion, rather
        # than a duplicate implementation of the successful-auth ordering.
        tree = ast.parse((HERE / 'dev-legacy-vault-smoke.py').read_text())
        run = next(node for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name == 'run_version')
        start = next(i for i, node in enumerate(run.body)
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Attribute) and node.value.func.attr == 'cli'
            and any(isinstance(arg, ast.Constant) and arg.value == '--vault' for arg in node.value.args))
        end = next(i for i, node in enumerate(run.body) if isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Call)
            and any(isinstance(arg, ast.Constant) and arg.value == 'migration_generated_replacement_super'
                for arg in node.value.args))
        code = compile(ast.Module(body=run.body[start:end + 1], type_ignores=[]),
            '<actual-v1-migration-block>', 'exec')
        keys = MemoryKeys()
        smoke = object.__new__(legacy.Smoke)
        smoke.keys = keys
        committed = dict(user=USER, keyring_account=OTHER, token='synthetic-token-never-report')
        def cli(env, *args, **kwargs):
            keys.created(OTHER, None)
            return {'summary': {'super_issued': 'unexpected-synthetic-super-never-report'}}
        smoke.cli = cli
        smoke.session = lambda env: committed
        account = {}
        with self.assertRaisesRegex(RuntimeError, '^migration_generated_replacement_super$') as raised:
            exec(code, {'self': smoke, 'upgraded_env': {}, 'UPSTREAM': legacy.UPSTREAM,
                'user': USER, 'password': PASSWORD, 'version': 1, 'account': account,
                'require': legacy.require})
        self.assertEqual(keys.entries, {('rsrs', 'pass:' + OTHER)})
        self.assertEqual(account['token'], committed['token'])
        report = keys.cleanup()
        self.assertTrue(report['passed'])
        self.assertFalse(keys.values)
        for forbidden in (PASSWORD, OTHER, USER, committed['token'],
                'unexpected-synthetic-super-never-report'):
            self.assertNotIn(forbidden, str(raised.exception) + json.dumps(report))

    def test_failed_auth_does_not_claim_alias(self):
        smoke = object.__new__(legacy.Smoke)
        smoke.keys = MemoryKeys()
        smoke.cli = lambda *a, **kw: (_ for _ in ()).throw(RuntimeError('auth_failed'))
        smoke.session = lambda env: {'user': USER}
        with self.assertRaisesRegex(RuntimeError, 'auth_failed'):
            smoke.password_login({}, USER, PASSWORD, 1, SUPER)
        self.assertFalse(smoke.keys.entries)

    def test_legacy_slot_names_are_bounded_to_owned_aliases_and_current_service(self):
        keys = MemoryKeys()
        for alias in (ALIAS, 'legacy-' + 'a' * 16, 'legacy-' + 'b' * 64):
            keys.reserve('rsrs', 'legacy-secret:' + alias)
        for prefix in ('super:', 'pass:'):
            keys.reserve('rsrs', prefix + 'legacy-' + 'b' * 64)
            with self.assertRaisesRegex(RuntimeError, '^credential_name_not_a_migration_fixture$'):
                keys.reserve('respire', prefix + 'legacy-' + 'b' * 64)
        for service, alias in (('1memory', ALIAS), ('rsrs', USER),
                               ('rsrs', 'legacy-' + 'a' * 17), ('rsrs', 'login-foreign'),
                               ('rsrs', 'legacy-' + 'a' * 63), ('rsrs', 'legacy-' + 'a' * 65),
                               ('rsrs', 'legacy-' + 'A' * 64)):
            with self.assertRaisesRegex(RuntimeError, '^credential_name_not_a_migration_fixture$'):
                keys.reserve(service, 'legacy-secret:' + alias)
        foreign_slot = 'legacy-secret:legacy-' + 'c' * 64
        keys.values['rsrs', foreign_slot] = 'foreign'
        with self.assertRaisesRegex(RuntimeError, '^fixture_credential_already_exists$'):
            keys.reserve('rsrs', foreign_slot)
        with self.assertRaisesRegex(RuntimeError, '^credential_not_owned_by_fixture$'):
            keys.remove('rsrs', foreign_slot)
        self.assertTrue(keys.cleanup()['passed'])
        self.assertEqual(keys.values, {('rsrs', foreign_slot): 'foreign'})

    def test_legacy_custody_and_failed_primary_readback_still_track_cleanup(self):
        for version in (1, 3):
            for backend, inline in (('native', False), ('native', True), ('kernel', False)):
                keys = MemoryKeys()
                keys.created(ALIAS, None if version == 1 else SUPER)
                keys.values['rsrs', 'legacy-secret:' + ALIAS] = 'synthetic-factor'
                session = dict(user=USER, keyring_account=ALIAS, vault_version=version,
                               legacy_secret_backend=backend)
                if inline:
                    session['secret' if version == 1 else 'secret_key'] = 'synthetic-factor'
                with self.assertRaises(RuntimeError):
                    keys.track_created_login(session, USER, None if version == 1 else SUPER, 'wrong')
                report = keys.cleanup()
                self.assertTrue(report['passed'])
                # A different backend is never claimed as this manager's slot.
                self.assertEqual(bool(keys.values), backend != 'native')
                self.assertNotIn('synthetic-factor', json.dumps(report))
        for backend in ('native', 'secret_service'):
            keys = MemoryKeys()
            keys.credential_backend = backend
            keys.values['rsrs', 'pass:' + ALIAS] = ''
            keys.values['rsrs', 'legacy-secret:' + ALIAS] = 'synthetic-factor'
            session = dict(user=USER, keyring_account=ALIAS, vault_version=1,
                           legacy_secret_backend=backend)
            keys.track_created_login(session, USER, None, '')
            self.assertEqual(keys.read('rsrs', 'pass:' + ALIAS), '')
            self.assertTrue(keys.cleanup()['passed'])
            self.assertFalse(keys.values)

    def test_mac_current_probe_preserves_session_and_keeps_failures(self):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        import sqlite3
        for failure in (None, 'show', 'session'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                code, salt, nonce, urk = 'A3-' + 'ab' * 18, 'cd' * 16, bytes(12), bytes(range(32))
                wrapped = legacy.PREFIX + AESGCM(legacy.v4_kek(code, salt, legacy.PREFIX)).encrypt(nonce, urk, None).hex()
                session = dict(user=USER, vault_version=4, keyring_account=ALIAS,
                               keyring_backend='native', kdf_salt=salt, wrapped_urk=wrapped, urk_nonce=nonce.hex())
                session_path = root / 'session.json'
                original = json.dumps(session).encode()
                session_path.write_bytes(original)
                ciphertext = legacy.PREFIX + AESGCM(legacy.hkdf(urk, None, b'rsrs:data:v1')).encrypt(nonce, b'payload', None).hex()
                with closing(sqlite3.connect(root / 'rsrs.db')) as db, db:
                    db.execute('CREATE TABLE memories(id TEXT, ciphertext TEXT, nonce TEXT)')
                    db.execute('INSERT INTO memories VALUES(?,?,?)', ('fixture', ciphertext, nonce.hex()))
                keys = MemoryKeys()
                keys.created(ALIAS, code)
                keys.track_created_login(session, USER, code, PASSWORD)
                smoke = object.__new__(profile.Smoke)
                smoke.root, smoke.keys, smoke.report, smoke.diagnostic_secrets = root, keys, {}, set()
                smoke.save = lambda: None
                def cli(env, *args):
                    if args[0] == 'keys-export':
                        Path(args[-1]).write_text('super password: ' + code + '\n', encoding='utf-8')
                        return {}
                    probe = json.loads(session_path.read_text(encoding='utf-8'))
                    self.assertEqual(probe['vault_version'], 4)
                    self.assertEqual(probe['keyring_account'], ALIAS)
                    self.assertNotIn('legacy_secret_backend', probe)
                    self.assertNotIn('secret', probe)
                    if failure == 'session':
                        session_path.write_text(json.dumps(dict(probe, token='changed')), encoding='utf-8')
                    if failure == 'show':
                        raise RuntimeError('synthetic_show_failed')
                    return {'details': {'entry': {'content': 'text'}}}
                smoke.cli = cli
                fixture = dict(account={'user': USER}, code=code, password=PASSWORD, id='fixture', text='text',
                               cipher=(ciphertext, nonce.hex()))
                with patch.object(profile.keyring_backend, 'owned_path', lambda path: path):
                    if failure:
                        expected_error = '^native_consumer_session_changed$' if failure == 'session' else '^synthetic_show_failed$'
                        with self.assertRaisesRegex(RuntimeError, expected_error):
                            smoke.verify_mac_native_credentials({'RSRS_DATA_DIR': str(root)}, fixture)
                    else:
                        for _ in range(2):
                            smoke.verify_mac_native_credentials({'RSRS_DATA_DIR': str(root)}, fixture)
                self.assertEqual(session_path.read_bytes(), original)
                self.assertFalse(list(root.glob('native-recovery-*.txt')))
                self.assertNotIn(('rsrs', 'legacy-secret:' + ALIAS), keys.values)
                self.assertTrue(keys.cleanup()['passed'])


class Item:
    def __init__(self, collection, attributes, value):
        self.collection, self.attributes, self.value = collection, attributes, value
    def get_attributes(self): return dict(self.attributes)
    def get_secret(self): return self.value.encode()
    def is_locked(self): return False
    def delete(self): self.collection.items.remove(self)


class Collection:
    def __init__(self): self.items = []
    def search_items(self, query):
        return [item for item in self.items if all(item.attributes.get(k) == v for k, v in query.items())]
    def get_all_items(self): return list(self.items)


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.keys = object.__new__(secret_service.SecretServiceKeys)
        native.TrackedKeys.__init__(self.keys, Path('unused'))
        self.keys.attribute_snapshots = {}
        self.keys.current_target_entries = set()
        self.keys.generic_schema_observed = set()
        self.keys.normalized_current_entries = set()
        self.keys.collection = Collection()
        self.keys.connection = self.keys.daemon = None
        self.session = dict(user=USER, keyring_account=ALIAS)
        for prefix, value in (('super:', SUPER), ('pass:', PASSWORD)):
            self.keys.collection.items.append(Item(self.keys.collection, self.keys.attributes('rsrs', prefix + ALIAS), value))
        self.keys.track_created_login(self.session, USER, SUPER, PASSWORD)

    def test_exact_alias_snapshot_and_narrow_normalization(self):
        import secrets
        registered = set()
        for _ in range(2):
            user = 'ci-migrate-' + secrets.token_hex(8)
            alias = 'login-' + secrets.token_hex(16)
            session = dict(user=user, keyring_account=alias)
            entries = {('rsrs', prefix + alias) for prefix in ('super:', 'pass:')}
            for prefix, value in (('super:', SUPER), ('pass:', PASSWORD)):
                self.keys.collection.items.append(Item(self.keys.collection,
                    self.keys.attributes('rsrs', prefix + alias), value))
            self.keys.track_created_login(session, user, SUPER, PASSWORD)
            before = {k: dict(v) for k, v in self.keys.attribute_snapshots.items()}
            # A previous registration must neither block a new pair nor admit it unchecked.
            for invalid_session, invalid_user in ((dict(session, user=USER), user),
                    (dict(session, keyring_account=OTHER), user), (session, 'foreign')):
                with self.assertRaises(RuntimeError):
                    self.keys.register_current_target(invalid_session, invalid_user)
                self.assertEqual(self.keys.current_target_entries, registered)
            entry = ('rsrs', 'pass:' + alias)
            snapshot = self.keys.attribute_snapshots.pop(entry)
            with self.assertRaisesRegex(RuntimeError, 'not_verified_owned_entry'):
                self.keys.register_current_target(session, user)
            self.keys.attribute_snapshots[entry] = snapshot
            self.keys.entries.remove(entry)
            with self.assertRaisesRegex(RuntimeError, 'not_verified_owned_entry'):
                self.keys.register_current_target(session, user)
            self.keys.entries.add(entry)
            item = self.keys.collection.items.pop()
            with self.assertRaisesRegex(RuntimeError, 'not_verified_owned_entry'):
                self.keys.register_current_target(session, user)
            self.keys.collection.items.append(item)
            item.attributes['extra'] = 'changed'
            with self.assertRaisesRegex(RuntimeError, 'attributes_changed'):
                self.keys.register_current_target(session, user)
            del item.attributes['extra']
            self.assertEqual(self.keys.current_target_entries, registered)
            self.keys.register_current_target(session, user)
            registered.update(entries)
            self.assertEqual(self.keys.current_target_entries, registered)
            with self.assertRaisesRegex(RuntimeError, 'registration_invalid'):
                self.keys.register_current_target(session, user)
            for current in self.keys.collection.items:
                if ('rsrs', current.attributes['username']) in entries:
                    current.attributes['xdg:schema'] = 'org.freedesktop.Secret.Generic'
            for prefix, value in (('super:', SUPER), ('pass:', PASSWORD)):
                self.assertEqual(self.keys.read('rsrs', prefix + alias), value)
            self.assertEqual(self.keys.attribute_snapshots, before)
            del item.attributes['xdg:schema']
            with self.assertRaisesRegex(RuntimeError, 'schema_reverted'):
                self.keys.read('rsrs', 'pass:' + alias)
            item.attributes['xdg:schema'] = 'foreign'
            with self.assertRaisesRegex(RuntimeError, 'schema_not_generic'):
                self.keys.read('rsrs', 'pass:' + alias)
            item.attributes['xdg:schema'] = 'org.freedesktop.Secret.Generic'
            item.attributes['application'] = 'foreign'
            with self.assertRaisesRegex(RuntimeError, 'attributes_mismatch'):
                self.keys.read('rsrs', 'pass:' + alias)
            item.attributes['application'] = 'rust-keyring'
        # Tracked but unregistered credentials retain strict raw schema snapshots.
        self.keys.collection.items[1].attributes['xdg:schema'] = 'org.freedesktop.Secret.Generic'
        with self.assertRaisesRegex(RuntimeError, 'attributes_changed'):
            self.keys.read('rsrs', 'pass:' + ALIAS)
        report = self.keys.cleanup()
        self.assertTrue(report['passed'])
        baseline = report['provider_schema_baseline']
        self.assertEqual(baseline['scope'],
                         'two_new_owned_current_credentials_per_verified_registration_only')
        self.assertEqual(baseline['registered_entries'], 4)
        self.assertEqual(baseline['observed_normalizations'], 4)
        self.assertFalse(baseline['initial_raw_snapshots_overwritten'])

    def test_foreign_user_alias_missing_untracked_rejected(self):
        for session in (dict(user='foreign', keyring_account=ALIAS), dict(user=USER, keyring_account=OTHER), dict(user=USER)):
            with self.assertRaises(RuntimeError):
                self.keys.register_current_target(session, USER)
            self.assertFalse(self.keys.current_target_entries)

    def test_missing_snapshot_or_credential_rejected(self):
        self.keys.attribute_snapshots.clear()
        with self.assertRaisesRegex(RuntimeError, 'not_verified_owned_entry'):
            self.keys.register_current_target(self.session, USER)
        self.assertFalse(self.keys.current_target_entries)

    def test_cleanup_never_deletes_untracked_private_item(self):
        foreign = Item(self.keys.collection, self.keys.attributes('rsrs', 'pass:' + OTHER), 'foreign')
        self.keys.collection.items.append(foreign)
        report = self.keys.cleanup()
        self.assertFalse(report['passed'])
        self.assertEqual(self.keys.collection.items, [foreign])
        self.assertIn({'code': 'fixture_collection_not_empty'}, report['remaining_entries'])
        self.assertEqual(report['collection_cleanup'],
                         {'passed': False, 'stage': 'empty_check', 'remaining_entries': 1})
        for forbidden in (PASSWORD, SUPER, USER, ALIAS, OTHER, 'foreign'):
            self.assertNotIn(forbidden, json.dumps(report))

    def test_business_cleanup_accepts_factor_slots_but_never_deletes_foreign_entries(self):
        self.keys.verify_owner = lambda: None
        for alias in (ALIAS, 'legacy-' + 'a' * 16, 'legacy-' + 'b' * 64):
            for prefix in ('pass:', 'super:', 'legacy-secret:'):
                self.keys.collection.items.append(Item(self.keys.collection,
                    self.keys.attributes('rsrs', prefix + alias), 'synthetic-factor'))
        foreign = Item(self.keys.collection,
            self.keys.attributes('rsrs', 'legacy-secret:' + USER), 'foreign')
        self.keys.collection.items.append(foreign)
        before = list(self.keys.collection.items)
        with self.assertRaisesRegex(RuntimeError, '^unexpected_private_credential$'):
            self.keys.cleanup_business_entries()
        self.assertEqual(self.keys.collection.items, before)
        self.assertEqual(self.keys.business_cleanup['deleted_entries'], 0)
        self.keys.collection.items.remove(foreign)
        self.keys.cleanup_business_entries()
        self.assertFalse(self.keys.collection.items)
        self.assertTrue(self.keys.business_cleanup['passed'])
        self.assertEqual(self.keys.business_classification['known_prefix_counts']['legacy-secret:'], 3)

    def test_all_tracked_cleanup_is_empty(self):
        self.keys.register_current_target(self.session, USER)
        report = self.keys.cleanup()
        self.assertTrue(report['passed'])
        self.assertEqual(report['provider_schema_baseline']['registered_entries'], 2)
        self.assertFalse(self.keys.collection.items)


class UpgradeLibraryStateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from contextlib import closing
        import hashlib
        import sqlite3
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        tree = ast.parse((HERE / 'test-real-m3-account-switch.py').read_text(encoding='utf-8'))
        functions = [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
                     and node.name in ('recover_fixture_urk', 'library_state', 'snapshot',
                                       'database_checkpoint_state', 'assert_database_checkpoint_preserved',
                                       'assert_historical_database_seed',
                                       'legacy_custody_alias', 'migrate_fixture_custody',
                                       'custody_consumer_error', 'verify_fixture_custody')]
        namespace = dict(vault_crypto=legacy, AESGCM=AESGCM, json=json, hashlib=hashlib, sqlite3=sqlite3, closing=closing,
                         pathlib=SimpleNamespace(Path=Path), sys=SimpleNamespace(platform='darwin'),
                         canonical_scope_path=lambda path: str(path.resolve()))
        exec(compile(ast.Module(body=functions, type_ignores=[]), '<upgrade-library-fixture>', 'exec'), namespace)
        cls.helpers = namespace

    def test_actual_seed_setup_covers_legacy_v1_v3_and_current_v4(self):
        import secrets
        import tempfile
        import time
        from types import SimpleNamespace
        tree = ast.parse((HERE / 'test-real-m3-account-switch.py').read_text(encoding='utf-8'))
        loop = next(node for node in tree.body if isinstance(node, ast.For))
        body = next(node for node in loop.body if isinstance(node, ast.Try)).body
        start = next(index for index, node in enumerate(body) if isinstance(node, ast.Assign)
                     and any(isinstance(target, ast.Name) and target.id == 'expected_urks' for target in node.targets))
        end = next(index for index, node in enumerate(body) if isinstance(node, ast.Assign)
                   and any(isinstance(target, ast.Name) and target.id == 'seed_env' for target in node.targets))
        code = compile(ast.Module(body=body[start:end], type_ignores=[]), '<actual-upgrade-seed>', 'exec')
        for historical in (False, True):
            with self.subTest(historical=historical), tempfile.TemporaryDirectory() as directory:
                main, alternate = Path(directory) / 'main', Path(directory) / 'alternate'
                main.mkdir(); alternate.mkdir()
                namespace = dict(self.helpers, main=main, alternate=alternate, secrets=secrets, time=time,
                                 args=SimpleNamespace(seed_binary=historical), code='A3-' + '12' * 18)
                exec(code, namespace)
                self.assertEqual(namespace['seed_vault_versions'], [1, 3] if historical else [4, 4])
                for profile in (main, alternate):
                    recovered = self.helpers['recover_fixture_urk'](
                        json.loads((profile / 'session.json').read_text()), namespace['recovery_factors'][str(profile)])
                    self.assertEqual(recovered, namespace['expected_urks'][str(profile)])

    def test_legacy_session_slot_changes_and_rebuilt_indexes_preserve_real_library_state(self):
        from contextlib import closing
        import sqlite3
        import tempfile
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.exceptions import InvalidTag
        for version in (1, 3, 4):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as directory:
                installation = Path(directory) / '.rsrs'
                profile = installation / 'accounts/alternate' if version == 3 else installation
                profile.mkdir(parents=True)
                urk, salt, nonce = bytes(range(32)), 'ab' * 16, bytes.fromhex('cd' * 12)
                factors = {'pass': PASSWORD, 'super': 'A3-' + '12' * 18,
                           'secret': 'original-secret', 'secret_key': 'original-secret-key'}
                def wrap(current, key=urk):
                    kek = (legacy.v4_kek(factors['super'], salt, legacy.PREFIX if current else '')
                           if version == 4 else legacy.legacy_kek(version,
                           factors['pass'] if version == 1 else factors['super'],
                           factors['secret'] if version == 1 else factors['secret_key'], salt, current=current))
                    return (legacy.PREFIX if current else '') + AESGCM(kek).encrypt(nonce, key, None).hex()
                def encrypt(current, payload=b'{"content":"original record"}', key=urk):
                    info = b'rsrs:data:v1' if current else b'onememory:data:v1'
                    return (legacy.PREFIX if current else '') + AESGCM(legacy.hkdf(key, None, info)).encrypt(nonce, payload, None).hex()
                session = dict(vault_version=version, kdf_salt=salt, urk_nonce=nonce.hex(),
                               wrapped_urk=wrap(False), **factors)
                (profile / 'session.json').write_text(json.dumps(session), encoding='utf-8')
                (profile / 'core-index').mkdir()
                (profile / 'core-index/index').write_bytes(b'old index')
                with closing(sqlite3.connect(profile / 'rsrs.db')) as db, db:
                    db.executescript('CREATE TABLE memories(id TEXT,ciphertext TEXT,nonce TEXT,dirty INTEGER,deleted INTEGER);'
                        'CREATE TABLE sync_outbox(seq INTEGER,operation TEXT);'
                        'CREATE TABLE core_artifacts(memory_id TEXT,model TEXT,source TEXT);')
                    db.execute('INSERT INTO memories VALUES(?,?,?,?,?)', ('original', encrypt(False), nonce.hex(), 1, 0))
                    db.execute('INSERT INTO sync_outbox VALUES(1,?)', ('pending original write',))
                    db.execute('INSERT INTO core_artifacts VALUES(?,?,?)', ('original', 'm3', 'old index source'))
                snapshot, state = self.helpers['snapshot'], self.helpers['library_state']
                before = snapshot(profile)
                expected = state(before, factors)
                self.assertEqual(expected[2], urk)
                if version in (1, 3):
                    alias = self.helpers['legacy_custody_alias'](profile, before[2])
                    slots = {'pass' if version == 1 else 'super': factors['pass' if version == 1 else 'super'],
                             'legacy-secret': factors['secret' if version == 1 else 'secret_key']}
                    migrate = self.helpers['migrate_fixture_custody']
                    for backend in ('native', 'secret_service'):
                        keys = MemoryKeys()
                        keys.credential_backend = backend
                        for slot in slots:
                            keys.reserve('rsrs', slot + ':' + alias)
                        # Failed readback must retain the original session and owned cleanup set.
                        with patch.object(keys, 'read', return_value='wrong'), self.assertRaises(RuntimeError):
                            migrate(profile, keys, (alias, version, slots), urk)
                        self.assertEqual(snapshot(profile), before)
                        self.assertTrue(keys.cleanup()['passed'])
                        migrate(profile, keys, (alias, version, slots), urk)
                        current = snapshot(profile)
                        self.assertEqual(current[:2], before[:2])
                        self.assertEqual(state(current, factors), expected)
                        committed = json.loads(current[2])
                        self.assertEqual(committed['legacy_secret_backend'], backend)
                        self.assertEqual(committed['keyring_backend'], backend)
                        self.assertEqual(committed['vault_version'], version)
                        self.assertFalse(set(factors) & committed.keys())
                        if backend == 'native':
                            config = installation / 'client.json'
                            config.write_text(json.dumps({'data_dir': str(profile)}), encoding='utf-8')
                            config_before = config.read_bytes()
                            env = {'RSRS_DATA_DIR': str(installation), 'RSRS_BIN_DIR': str(installation / 'bin'),
                                   'RSRS_RUNTIME_BIN': str(installation / 'bin/runtime/dev23/rsrs-runtime')}
                            keys.keychain = profile / 'synthetic.keychain'
                            keys._security = Mock(return_value=SimpleNamespace(returncode=0))
                            def consume(command, *, env, timeout):
                                self.assertEqual(env['RSRS_DATA_DIR'], str(installation))
                                self.assertEqual(json.loads(config.read_bytes())['data_dir'], str(profile))
                                self.assertEqual(env, expected_env)
                                self.assertEqual(command, ['fixture-cli', '--json', 'show', 'original'])
                                return SimpleNamespace(returncode=0, stderr=b'', stdout=json.dumps({
                                    'status': 'ok', 'details': {'entry': {'content': 'original record'}}}).encode())
                            expected_env = dict(env)
                            verify = self.helpers['verify_fixture_custody']
                            with patch.dict(self.helpers, captured_run=consume):
                                receipt = verify(profile, keys, (alias, version, slots), urk, 'fixture-cli', env)
                            self.assertEqual(receipt['consumer'], 'cli_authenticated_decryption')
                            self.assertEqual(config.read_bytes(), config_before)
                            self.assertEqual(snapshot(profile), current)
                            for returncode, message in ((1, 'unlock Runtime does not own the selected profile'),
                                                        (1, 'runtime request belongs to another installation'),
                                                        (0, 'host session credential read failed'), (1, 'unknown')):
                                output = SimpleNamespace(returncode=returncode,
                                    stdout=json.dumps({'status': 'fail', 'errors': [message + ' ' + PASSWORD]}).encode(),
                                    stderr=(SUPER + ' original record').encode())
                                with patch.dict(self.helpers, captured_run=Mock(return_value=output)), \
                                        self.assertRaises(AssertionError) as failed:
                                    verify(profile, keys, (alias, version, slots), urk, 'fixture-cli', env)
                                diagnostic = str(failed.exception)
                                self.assertIn(message if message != 'unknown' else 'unclassified', diagnostic)
                                self.assertNotIn(PASSWORD, diagnostic)
                                self.assertNotIn(SUPER, diagnostic)
                                self.assertNotIn('original record', diagnostic)
                            config.write_text(json.dumps({'data_dir': str(profile / 'wrong')}), encoding='utf-8')
                            child = Mock()
                            with patch.dict(self.helpers, captured_run=child), \
                                    self.assertRaisesRegex(AssertionError, 'account is not selected'):
                                verify(profile, keys, (alias, version, slots), urk, 'fixture-cli', env)
                            child.assert_not_called()
                        self.assertTrue(keys.cleanup()['passed'])
                        self.assertFalse(keys.values)
                        (profile / 'session.json').write_bytes(before[2])
                migrated = {key: value for key, value in session.items() if key not in factors}
                migrated.update(wrapped_urk=wrap(True), keyring_account='legacy-' + '1' * 16,
                                keyring_backend='native')
                (profile / 'session.json').write_text(json.dumps(migrated), encoding='utf-8')
                (profile / 'core-index/index').write_bytes(b'rebuilt index')
                with closing(sqlite3.connect(profile / 'rsrs.db')) as db, db:
                    db.execute('UPDATE memories SET ciphertext=?', (encrypt(True),))
                    db.execute('UPDATE core_artifacts SET source=?', ('rebuilt source',))
                self.assertNotEqual(snapshot(profile), before)
                self.assertEqual(state(snapshot(profile), factors), expected)
                for field in ('super',) if version == 4 else ('pass', 'secret') if version == 1 else ('super', 'secret_key'):
                    with self.subTest(wrong_factor=field), self.assertRaises(InvalidTag):
                        state(snapshot(profile), {**factors, field: 'A3-' + '34' * 18 if field == 'super' and version == 4 else 'wrong'})
                for mutation, restore in (("UPDATE memories SET id='replacement'", "UPDATE memories SET id='original'"),
                        ('DELETE FROM memories', None), ('UPDATE memories SET dirty=0', 'UPDATE memories SET dirty=1'),
                        ('UPDATE memories SET deleted=1', 'UPDATE memories SET deleted=0'),
                        ('DELETE FROM sync_outbox', "INSERT INTO sync_outbox VALUES(1,'pending original write')")):
                    with closing(sqlite3.connect(profile / 'rsrs.db')) as db, db:
                        db.execute(mutation)
                    self.assertNotEqual(state(snapshot(profile), factors), expected)
                    with closing(sqlite3.connect(profile / 'rsrs.db')) as db, db:
                        if restore is None:
                            db.execute('INSERT INTO memories VALUES(?,?,?,?,?)', ('original', encrypt(True), nonce.hex(), 1, 0))
                        else:
                            db.execute(restore)
                with closing(sqlite3.connect(profile / 'rsrs.db')) as db, db:
                    db.execute('UPDATE memories SET ciphertext=?', (encrypt(True, b'changed record'),))
                self.assertNotEqual(state(snapshot(profile), factors), expected)
                replacement_urk = bytes(reversed(range(32)))
                migrated['wrapped_urk'] = wrap(True, replacement_urk)
                (profile / 'session.json').write_text(json.dumps(migrated), encoding='utf-8')
                with self.assertRaises(InvalidTag):
                    state(snapshot(profile), factors)
                with closing(sqlite3.connect(profile / 'rsrs.db')) as db, db:
                    db.execute('UPDATE memories SET ciphertext=?', (encrypt(True, key=replacement_urk),))
                self.assertEqual(state(snapshot(profile), factors)[0], expected[0])
                self.assertNotEqual(state(snapshot(profile), factors), expected)

        checkpoint = self.helpers['database_checkpoint_state']
        preserved = self.helpers['assert_database_checkpoint_preserved']
        key, nonce = bytes(range(32)), bytes.fromhex('cd' * 12)
        payload = json.dumps({'content': 'legacy association', 'supersedes': 'ancestor',
                              'superseded_by': 'successor', 'see_also': ['peer']}).encode()
        old = AESGCM(legacy.hkdf(key, None, b'onememory:data:v1')).encrypt(nonce, payload, None).hex()
        raw = ([[('entry', old, nonce.hex(), 1, 0)]], [], b'')
        seeded = ([[('entry', old, nonce.hex(), 1, 0), ('deleted', old, nonce.hex(), 1, 1)],
                   [('pending operation',)], []], [], b'')
        require_seed = self.helpers['assert_historical_database_seed']
        require_seed(seeded)
        for memories, outbox in ((seeded[0][0][:1], seeded[0][1]),
                                (seeded[0][0][1:], seeded[0][1]),
                                ([seeded[0][0][0], ('deleted', '', '', 1, 1)], seeded[0][1]),
                                ([seeded[0][0][0], ('deleted', old, nonce.hex(), 0, 1)], seeded[0][1]),
                                (seeded[0][0], [])):
            with self.assertRaises(AssertionError):
                require_seed(([memories, outbox, []], [], b''))
        records = [('entry', legacy.decrypt_content(key, old, nonce.hex()), 1, 0)]
        before = checkpoint(Path('.'), 'v1.0.11-dev.1', raw, records)
        self.assertTrue(before['legacy_domain'])
        after = {**before, 'legacy_domain': False, 'links': before['links'] + [('new', '', '', ())]}
        preserved(before, after)
        with self.assertRaisesRegex(AssertionError, 'relation fields changed'):
            preserved(before, {**after, 'links': [('entry', 'ancestor', '', ('peer',))]})
        with self.assertRaisesRegex(ValueError, 'unsupported database checkpoint'):
            checkpoint(Path('.'), 'v1.0.15-dev.10', raw, records)

        with tempfile.TemporaryDirectory() as directory:
            profile = Path(directory)
            with closing(sqlite3.connect(profile / 'rsrs.db')) as db, db:
                db.executescript('CREATE TABLE witness_log(schema_version,library_id,seq,ts,action,entry_id,'
                    'previous_entry_id,before_digest,after_digest,prev,hash);'
                    'CREATE TABLE query_log(id INTEGER PRIMARY KEY,request_id TEXT);'
                    'CREATE TABLE query_feedback(query_log_id INTEGER,memory_id TEXT,good INTEGER,'
                    'source TEXT,marked_at INTEGER,revision INTEGER);')
                event = (1, 'library', 1, 'stamp', 'create', 'entry', '', None, 'digest', 'previous', 'hash')
                db.execute('INSERT INTO witness_log VALUES(?,?,?,?,?,?,?,?,?,?,?)', event)
                db.execute("INSERT INTO query_log VALUES(1,'request')")
                db.execute("INSERT INTO query_feedback VALUES(1,'entry',1,'human',1,1)")
            before = checkpoint(profile, 'v1.0.17-dev.6', raw, records)
            self.assertTrue(before['witness'] and before['requests'] and before['feedback'])
            self.assertFalse(before['recovery_table'])
            with closing(sqlite3.connect(profile / 'rsrs.db')) as db, db:
                db.execute('INSERT INTO witness_log VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                           (1, 'library', 2, 'later', 'update', 'entry', 'entry', 'digest', 'next', 'hash', 'next-hash'))
            preserved(before, checkpoint(profile, 'v1.0.17-dev.6', raw, records))
            with closing(sqlite3.connect(profile / 'rsrs.db')) as db, db:
                db.execute("UPDATE witness_log SET after_digest='changed' WHERE seq=1")
            with self.assertRaisesRegex(AssertionError, 'witness prefix changed'):
                preserved(before, checkpoint(profile, 'v1.0.17-dev.6', raw, records))
            with closing(sqlite3.connect(profile / 'rsrs.db')) as db, db:
                db.execute("UPDATE witness_log SET after_digest='digest' WHERE seq=1")
                db.execute('DELETE FROM query_feedback')
            with self.assertRaisesRegex(AssertionError, 'explicit feedback changed'):
                preserved(before, checkpoint(profile, 'v1.0.17-dev.6', raw, records))


class OriginalFactorTests(unittest.TestCase):
    def test_original_v1_factors_unwrap_unchanged_urk_and_reject_wrong_factors(self):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.exceptions import InvalidTag
        salt, nonce, urk, secret = 'ab' * 16, bytes.fromhex('cd' * 12), bytes(range(32)), 'original-account-secret'
        old = AESGCM(legacy.legacy_kek(1, PASSWORD, secret, salt)).encrypt(nonce, urk, None)
        recovered = AESGCM(legacy.legacy_kek(1, PASSWORD, secret, salt)).decrypt(nonce, old, None)
        new = AESGCM(legacy.legacy_kek(1, PASSWORD, secret, salt, current=True)).encrypt(nonce, recovered, None)
        self.assertEqual(AESGCM(legacy.legacy_kek(1, PASSWORD, secret, salt, current=True)).decrypt(nonce, new, None), urk)
        for password, factor in (('wrong', secret), (PASSWORD, 'wrong')):
            with self.assertRaises(InvalidTag):
                AESGCM(legacy.legacy_kek(1, password, factor, salt, current=True)).decrypt(nonce, new, None)

    def test_host_commit_assertion_rejects_plaintext_volatile_backend_wrong_environment(self):
        tree = ast.parse((HERE / 'dev-legacy-vault-smoke.py').read_text())
        assertion = next(node for node in ast.walk(tree) if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name) and node.func.id == 'require'
            and len(node.args) == 2 and isinstance(node.args[1], ast.Constant)
            and node.args[1].value == 'headless_v1_persistent_password_commit_invalid')
        code = compile(ast.Expression(assertion), '<fixture-assertion>', 'eval')
        for backend in ('native', 'secret_service'):
            eval(code, {'require': legacy.require, 'headless': {'keyring_backend': backend},
                'headless_env': {'RSRS_PASS': PASSWORD}, 'password': PASSWORD})
        for session, env in (({}, {'RSRS_PASS': PASSWORD}),
                ({'keyring_backend': 'kernel'}, {'RSRS_PASS': PASSWORD}),
                ({'keyring_backend': 'native', 'pass': PASSWORD}, {'RSRS_PASS': PASSWORD}),
                ({'keyring_backend': 'native'}, {'RSRS_PASS': 'wrong'})):
            with self.assertRaisesRegex(RuntimeError, '^headless_v1_persistent_password_commit_invalid$'):
                eval(code, {'require': legacy.require, 'headless': session,
                    'headless_env': env, 'password': PASSWORD})

    def test_native_only_proofs_and_independent_tracking_remain_in_suite(self):
        legacy_text = (HERE / 'dev-legacy-vault-smoke.py').read_text()
        profile_text = (HERE / 'dev-profile-migration-smoke.py').read_text()
        for code in ('headless_v1_changed_original_factors', 'headless_v1_changed_urk',
                     'new_device_ciphertext_differs', 'migration_changed_urk', 'original_source_changed',
                     'full_migration_not_reencrypted', 'old_authentication_hash_still_accepted'):
            self.assertIn(code, legacy_text)
        self.assertIn('authorization_fallback_and_absent_native_store_not_tested', legacy_text)
        database = next(node for node in ast.walk(ast.parse(legacy_text))
            if isinstance(node, ast.FunctionDef) and node.name == 'database_sync')
        tombstone = next(node for node in ast.walk(database) if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name) and node.func.id == 'require'
            and len(node.args) == 2 and isinstance(node.args[1], ast.Constant)
            and node.args[1].value == 'new_device_tombstone_not_propagated')
        assertion = compile(ast.Expression(tombstone), '<remote-tombstone-contract>', 'eval')
        head = {'id': 'deleted-fixture', 'deleted': True, 'ciphertext': '', 'nonce': ''}
        scope = dict(require=legacy.require, deleted='deleted-fixture',
            observed={'deleted-fixture': ('deleted-fixture', '', '', 1)}, heads={'deleted-fixture': head})
        eval(assertion, scope)
        for wrong in ({}, dict(head, deleted=False), dict(head, id='unrelated'),
                      dict(head, ciphertext='stale'), dict(head, nonce='stale')):
            with self.subTest(tombstone=wrong):
                with self.assertRaisesRegex(RuntimeError, '^new_device_tombstone_not_propagated$'):
                    eval(assertion, dict(scope, heads={'deleted-fixture': wrong}))
        with self.assertRaisesRegex(RuntimeError, '^new_device_tombstone_not_propagated$'):
            eval(assertion, dict(scope, observed={}))
        tree = ast.parse(profile_text)
        case = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == 'case')
        body = ast.unparse(case)
        self.assertLess(body.index('self.keys.track_created_login(independent,'), body.index("self.cli(remote, 'sync')"))
        setup = next(node for node in ast.walk(case) if isinstance(node, ast.Assign)
                     and isinstance(node.value, ast.Constant) and node.value.value == 'independent_current_login')
        login = next(node for node in ast.walk(case) if isinstance(node, ast.Expr)
                     and isinstance(node.value, ast.Call) and ast.unparse(node.value.func) == 'self.cli'
                     and node.value.args and ast.unparse(node.value.args[0]) == 'remote')
        statements = sorted((node for node in ast.walk(case) if isinstance(node, ast.stmt)
                             and setup.lineno <= node.lineno < login.lineno), key=lambda node: node.lineno)
        with tempfile.TemporaryDirectory() as temporary:
            smoke = object.__new__(profile.Smoke)
            smoke.root, smoke.model = Path(temporary), Path(temporary) / 'models'
            smoke.args, smoke.base_env, smoke.keys = SimpleNamespace(binary=Path(temporary) / 'rsrs'), {}, None
            smoke.report, smoke.save = {}, Mock()
            fixture = {'code': SUPER}
            scope = dict(self=smoke, user=USER, fixture=fixture, Path=Path, require=profile.require)
            with patch.object(profile.support, 'install_published_runtime') as install:
                exec(compile(ast.Module(body=statements, type_ignores=[]), '<actual-independent-profile>', 'exec'), scope)
            remote = scope['remote']
            session = Path(remote['RSRS_DATA_DIR']) / 'session.json'
            self.assertFalse(session.exists())
            self.assertFalse((session.parent / 'rsrs.db').exists())
            self.assertTrue(session.parent.is_relative_to(smoke.root))
            self.assertEqual(remote['RSRS_SUPER'], SUPER)
            self.assertEqual(smoke.report['fixture_operation'], 'independent_current_login')
            install.assert_called_once()
            self.assertEqual(fixture, {'code': SUPER})
            # A partial named session is an existing recovery target, not a fresh login.
            session.write_text(json.dumps({'user': USER}), encoding='utf-8')
            guard = next(node.value for node in statements if isinstance(node, ast.Expr)
                         and isinstance(node.value, ast.Call) and ast.unparse(node.value.func) == 'require')
            with self.assertRaisesRegex(RuntimeError, '^independent_profile_not_empty$'):
                eval(compile(ast.Expression(guard), '<independent-profile-guard>', 'eval'), scope)
        for code in ('existing_target_data_overwritten', 'existing_target_session_overwritten'):
            self.assertIn(code, body)
        self.assertIn('self.read_entry(current_env,', body)
        seed = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == 'seed')
        seed_text = ast.unparse(seed)
        for removed in ('seed_legacy_native_credentials', 'remove_current_native_credentials',
                        'rewrite_legacy_endpoint', 'https://api.1memory.ai', 'https://api.memocap.ai',
                        'https://api.respire.ai', '/api/self/vault', 'self.keys.put(', 'self.keys.remove('):
            self.assertNotIn(removed, seed_text)
        self.assertIn('source_alias', seed_text)
        self.assertIn("dict(default, RSRS_SUPER=fixture['code'])", body)
        self.assertLess(body.index("self.cli(user_env, 'login', '--interactive'"),
                        body.index('self.read_entry(user_env,'))
        shared = load('db_only_shared_gate', 'dev-smoke-gate.py')
        native_gate = load('db_only_secret_service_gate', 'dev-secret-service-migration-gate.py')
        self.assertEqual(set(profile.REQUIRED), shared.MIGRATION)
        self.assertEqual(native_gate.REQUIRED, set(profile.REQUIRED) |
                         {'secret_service_current_credentials_for_legacy_db'})
        workflow = (HERE.parent / '.github/workflows/migration-keyring-check.yml').read_text()
        self.assertIn("module.REQUIRED-{'secret_service_current_credentials_for_legacy_db'}", workflow)
        self.assertNotIn('secret_service_legacy_fields_and_aliases', workflow)
        self.assertTrue({'legacy_keys_migrated_without_super_override', 'legacy_api_defaults_rewritten'}
                        .isdisjoint(shared.MIGRATION))
        for retained in ('migration_wrong_key_rejected', 'migration_incompatible_primary_keys_rejected',
                         'migration_interrupted_restart_recovered', 'migration_repeated_start_idempotent',
                         'migrated_outbox_sync_and_independent_decrypt'):
            self.assertIn(retained, shared.MIGRATION)
        negative = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
                        and node.name == 'negative_cases')
        rejection = next(node for node in ast.walk(negative) if isinstance(node, ast.Call)
                         and isinstance(node.func, ast.Name) and node.func.id == 'require'
                         and len(node.args) == 2 and isinstance(node.args[1], ast.Constant)
                         and node.args[1].value == 'wrong_key_not_rejected_by_runtime')
        check = compile(ast.Expression(rejection), '<wrong-key-rejection-guard>', 'eval')
        accepted_rejection = dict(status='fail', errors=[
            'migration_stage=exchange; migration_exchange=runtime_migration_outcome_unknown'])
        eval(check, dict(require=profile.require, result=SimpleNamespace(returncode=1),
                         rejected=accepted_rejection))
        for exit_code, envelope in ((0, accepted_rejection), (1, dict(status='ok')),
                (1, dict(status='fail', errors=['migration_stage=host_candidates'])),
                *((1, dict(status='fail', errors=['migration_stage=exchange; migration_exchange=' + reason]))
                  for reason in ('channel', 'deadline', 'spawn', 'frame', 'unclassified',
                                 'runtime_scope_mismatch', 'runtime_unauthorized')),
                (1, dict(status='fail', errors=['migration_stage=exchange'])),
                (1, dict(status='fail', errors=['unrelated CLI failure']))):
            with self.subTest(exit_code=exit_code, envelope=envelope), \
                    self.assertRaisesRegex(RuntimeError, '^wrong_key_not_rejected_by_runtime$'):
                eval(check, dict(require=profile.require, result=SimpleNamespace(returncode=exit_code),
                                 rejected=envelope))


if __name__ == '__main__':
    unittest.main()
