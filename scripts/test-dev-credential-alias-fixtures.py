#!/usr/bin/env python3
"""Offline fixture regressions; no native credential store or network access."""
import ast
from contextlib import closing
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

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


class MemoryKeys(native.TrackedKeys):
    credential_backend = 'native'
    def __init__(self):
        super().__init__(Path('unused'))
        self.values = {}
        self.reads = []

    def _read(self, service, slot):
        self.reads.append((service, slot))
        return self.values.get((service, slot))

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

    def test_all_password_login_versions_track_before_return(self):
        for version in (1, 2, 3):
            with self.subTest(version=version):
                keys = MemoryKeys()
                smoke = object.__new__(legacy.Smoke)
                smoke.keys = keys
                aliases = iter((ALIAS, OTHER))
                current = {}
                def cli(env, *args, **kwargs):
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
        for version in (1, 2, 3):
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
                self.assertEqual(len(prompts), 2 if version == 1 else 3)
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

    def test_committed_session_tracked_even_when_post_auth_checks_fail(self):
        for reason in ('fixture_tty_missing_prompt', 'invalid_cli_json_login', 'owned_runtime_stop_failed'):
            keys = MemoryKeys()
            smoke = object.__new__(legacy.Smoke)
            smoke.keys = keys
            current = {'user': USER}
            def cli(*args, **kwargs):
                keys.created(ALIAS)
                current.update(keyring_account=ALIAS, token='synthetic-token')
                raise RuntimeError(reason)
            smoke.cli = cli
            smoke.session = lambda env: dict(current)
            with self.assertRaisesRegex(RuntimeError, '^' + reason + '$'):
                smoke.password_login({}, USER, PASSWORD, 2, SUPER)
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

    def test_mac_v1_probe_removes_temporary_slot_restores_session_and_keeps_failures(self):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        import sqlite3
        for failure in (None, 'show', 'cleanup'):
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
                    keys.values['rsrs', 'legacy-secret:' + ALIAS] = probe.pop('secret')
                    probe['legacy_secret_backend'] = 'native'
                    session_path.write_text(json.dumps(probe), encoding='utf-8')
                    if failure == 'show':
                        raise RuntimeError('synthetic_show_failed')
                    return {'details': {'entry': {'content': 'text'}}}
                smoke.cli = cli
                remove = keys._remove
                if failure == 'cleanup':
                    keys._remove = lambda *args: (_ for _ in ()).throw(RuntimeError('synthetic_cleanup_failed'))
                fixture = dict(account={'user': USER}, code=code, password=PASSWORD, id='fixture', text='text',
                               cipher=(ciphertext, nonce.hex()))
                with patch.object(profile.keyring_backend, 'owned_path', lambda path: path):
                    if failure:
                        with self.assertRaisesRegex(RuntimeError, '^synthetic_' + failure + '_failed$'):
                            smoke.verify_mac_native_credentials({'RSRS_DATA_DIR': str(root)}, fixture)
                    else:
                        for _ in range(2):
                            smoke.verify_mac_native_credentials({'RSRS_DATA_DIR': str(root)}, fixture)
                self.assertEqual(session_path.read_bytes(), original)
                self.assertFalse(list(root.glob('native-recovery-*.txt')))
                self.assertEqual(('rsrs', 'legacy-secret:' + ALIAS) in keys.values, failure == 'cleanup')
                keys._remove = remove
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
        before = {k: dict(v) for k, v in self.keys.attribute_snapshots.items()}
        self.keys.register_current_target(self.session, USER)
        self.assertEqual(self.keys.current_target_entries, set(before))
        for item in self.keys.collection.items:
            item.attributes['xdg:schema'] = 'org.freedesktop.Secret.Generic'
        self.assertEqual(self.keys.read('rsrs', 'pass:' + ALIAS), PASSWORD)
        self.assertEqual(self.keys.attribute_snapshots, before)
        self.keys.collection.items[1].attributes['application'] = 'foreign'
        with self.assertRaisesRegex(RuntimeError, 'attributes_mismatch'):
            self.keys.read('rsrs', 'pass:' + ALIAS)

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
                     and node.name in ('recover_fixture_urk', 'library_state', 'snapshot')]
        namespace = dict(vault_crypto=legacy, AESGCM=AESGCM, json=json, hashlib=hashlib, sqlite3=sqlite3, closing=closing)
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
                profile = Path(directory)
                urk, salt, nonce = bytes(range(32)), 'ab' * 16, bytes.fromhex('cd' * 12)
                factors = {'pass': PASSWORD, 'super': 'A3-' + '12' * 18,
                           'secret': 'original-secret', 'secret_key': 'original-secret-key'}
                def wrap(current, key=urk):
                    kek = (legacy.v4_kek(factors['super'], salt, legacy.PREFIX if current else '')
                           if version == 4 else legacy.legacy_kek(version,
                           factors['pass'] if version == 1 else factors['super'],
                           factors['secret'] if version == 1 else factors['secret_key'], salt, current=current))
                    return (legacy.PREFIX if current else '') + AESGCM(kek).encrypt(nonce, key, None).hex()
                def encrypt(current, payload=b'original record', key=urk):
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
        tree = ast.parse(profile_text)
        case = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == 'case')
        body = ast.unparse(case)
        self.assertLess(body.index('self.keys.track_created_login(independent,'), body.index("self.cli(remote, 'sync')"))
        for code in ('existing_target_data_overwritten', 'existing_target_session_overwritten'):
            self.assertIn(code, body)
        self.assertIn('self.read_entry(current_env,', body)


if __name__ == '__main__':
    unittest.main()
