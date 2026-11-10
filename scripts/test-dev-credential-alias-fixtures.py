#!/usr/bin/env python3
"""Offline fixture regressions; no native credential store or network access."""
import ast
import importlib.util
import json
from pathlib import Path
import sys
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
                    current.update(user=USER, keyring_account=alias)
                    return {'summary': {'ok': True}}
                smoke.cli = cli
                smoke.session = lambda env: current
                for env in ({}, {'RSRS_PASS': PASSWORD}):
                    smoke.password_login(env, USER, PASSWORD, version, SUPER)
                    self.assertIn(('rsrs', 'pass:' + current['keyring_account']), keys.entries)
                self.assertEqual(len(keys.entries), 2 if version == 1 else 4)
                self.assertTrue(keys.cleanup()['passed'])
                self.assertFalse(keys.values)

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
        smoke.session = lambda env: self.fail('read after failed auth')
        with self.assertRaisesRegex(RuntimeError, 'auth_failed'):
            smoke.password_login({}, USER, PASSWORD, 1, SUPER)
        self.assertFalse(smoke.keys.entries)


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
        self.assertIn({'code': 'fixture_collection_cleanup_failed'}, report['remaining_entries'])
        for forbidden in (PASSWORD, SUPER, USER, ALIAS, OTHER, 'foreign'):
            self.assertNotIn(forbidden, json.dumps(report))

    def test_all_tracked_cleanup_is_empty(self):
        self.keys.register_current_target(self.session, USER)
        report = self.keys.cleanup()
        self.assertTrue(report['passed'])
        self.assertEqual(report['provider_schema_baseline']['registered_entries'], 2)
        self.assertFalse(self.keys.collection.items)


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
