"""Synthetic environment/credential metadata tests; no native service or product."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location('runtime_credentials', Path(__file__).with_name('dev-runtime-smoke.py'))
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)
BUS = 'unix:path=/tmp/owned-fixture-bus,guid=' + 'a' * 32


class EnvironmentTests(unittest.TestCase):
    def test_private_bus_contract(self):
        with patch.object(runtime.sys, 'platform', 'linux'):
            self.assertEqual(runtime.private_fixture_bus({'RSRS_SS_FIXTURE_BUS': 'private', 'DBUS_SESSION_BUS_ADDRESS': BUS}), BUS)
            for flag in (None, '', 'host', 'PRIVATE', 'private '):
                self.assertIsNone(runtime.private_fixture_bus({'RSRS_SS_FIXTURE_BUS': flag, 'DBUS_SESSION_BUS_ADDRESS': BUS}))
            for bus in ('', 'unix:', 'tcp:host=localhost', 'unix:path=', 'unix:path=/tmp/a;unix:path=/host',
                        'unix:path=/tmp/a\n', 'unix:path=/tmp/a,guid=invalid'):
                self.assertIsNone(runtime.private_fixture_bus({'RSRS_SS_FIXTURE_BUS': 'private', 'DBUS_SESSION_BUS_ADDRESS': bus}))
        with patch.object(runtime.sys, 'platform', 'darwin'):
            self.assertIsNone(runtime.private_fixture_bus({'RSRS_SS_FIXTURE_BUS': 'private', 'DBUS_SESSION_BUS_ADDRESS': BUS}))

    def test_setup_preserves_stripping_and_private_bus_and_failure(self):
        for private, fail in ((True, False), (True, True), (False, True)):
            with self.subTest(private=private, fail=fail), tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                binary = base / 'fixture-bytes-not-executable'
                binary.write_bytes(b'synthetic')
                args = SimpleNamespace(root=base / 'owned', source_sha='a'*40, binary=binary,
                    binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(), version='test', runtime_binary=None)
                smoke = runtime.Smoke.__new__(runtime.Smoke)
                smoke.args, smoke.root, smoke.report = args, args.root, {'cases': {}}
                stripped = ['ONEMEMORY_X', 'RESPIRE_X', 'XDG_OTHER', 'DS_X', 'JEV_X', 'GNOME_X',
                    'SECRET_TOKEN', 'SECRET_API_KEY', 'MY_TEST_MODE_SETTING', 'APPDATA', 'LOCALAPPDATA',
                    'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy',
                    'DBUS_STARTER_ADDRESS', 'DBUS_STARTER_BUS_TYPE', 'DBUS_SESSION_BUS_PID', 'SSH_AUTH_SOCK', 'RSRS_SUPER']
                env = {key: 'sensitive-sentinel' for key in stripped}
                env.update(RUNNER_TEMP=directory, GITHUB_ACTIONS='true', RUNNER_ENVIRONMENT='github-hosted',
                           HOME='/host', USERPROFILE='/host', DBUS_SESSION_BUS_ADDRESS=BUS, KEEP='ok')
                if private:
                    env['RSRS_SS_FIXTURE_BUS'] = 'private'
                with patch.dict(os.environ, env, clear=True), patch.object(runtime.platform, 'system', return_value='Linux'), \
                     patch.object(runtime.sys, 'platform', 'linux'), patch.object(runtime, 'RuntimeProviderKeys') as keys, \
                     patch.object(runtime, 'install_published_runtime', return_value=None) as install, \
                     patch.object(smoke, 'direct', return_value={'summary': {'version': 'test'}}), \
                     patch.object(runtime.socket, 'socket') as socket:
                    socket.return_value.__enter__.return_value.getsockname.return_value = ('127.0.0.1', 12345)
                    if fail:
                        keys.side_effect = runtime.Failure('private_runtime_fixture_bus_required')
                        with self.assertRaisesRegex(runtime.Failure, '^private_runtime_fixture_bus_required$'):
                            smoke.setup()
                        install.assert_not_called()
                    else:
                        smoke.setup()
                    self.assertFalse(set(stripped) & smoke.env.keys())
                    self.assertEqual(smoke.env['HOME'], str(args.root / 'home'))
                    self.assertEqual(smoke.env['USERPROFILE'], str(args.root / 'home'))
                    self.assertEqual(smoke.env['KEEP'], 'ok')
                    self.assertEqual(smoke.env.get('DBUS_SESSION_BUS_ADDRESS'), BUS if private else None)
                    self.assertEqual(smoke.env.get('RSRS_SS_FIXTURE_BUS'), 'private' if private else None)
                    self.assertNotIn('sensitive-sentinel', json.dumps(smoke.report))


class ProviderTests(unittest.TestCase):
    def setUp(self):
        self.keys = runtime.RuntimeProviderKeys.__new__(runtime.RuntimeProviderKeys)
        self.keys.slots = set()
        self.keys.owner = ('owned-name',)
        self.keys.current_owner = Mock(return_value=self.keys.owner)
        self.items = {}
        self.keys.collection = Mock()
        self.keys.collection.search_items.side_effect = lambda attrs: list(self.items.get(attrs['username'], []))

    def item(self, slot):
        item = Mock()
        item.get_attributes.return_value = self.keys.attributes(slot)
        item.delete.side_effect = lambda: self.items[slot].remove(item)
        self.items.setdefault(slot, []).append(item)
        return item

    def test_exact_four_slots_cleanup_never_reads_secret_or_login(self):
        slots = ['classify:last-backend', 'classify:ds-last-base', 'classify:ds@127.0.0.1:12345',
                 'classify:ds-model@127.0.0.1:12345']
        login = self.item('super:login-' + 'a'*32)
        for slot in slots:
            self.keys.reserve(slot)
        items = [self.item(slot) for slot in slots]
        self.assertTrue(self.keys.cleanup())
        for item in items:
            item.delete.assert_called_once()
            item.get_secret.assert_not_called()
        login.delete.assert_not_called()
        self.keys.collection.get_all_items.assert_not_called()
        self.assertTrue(self.keys.cleanup())

    def test_collision_not_claimed_deleted_or_read(self):
        item = self.item('classify:ds-last-base')
        with self.assertRaisesRegex(runtime.Failure, 'runtime_provider_slot_exists'):
            self.keys.reserve('classify:ds-last-base')
        self.assertFalse(self.keys.slots)
        self.assertTrue(self.keys.cleanup())
        item.delete.assert_not_called()
        item.get_secret.assert_not_called()

    def test_unexpected_slot_owner_attributes_ambiguity_and_deletion_fail_closed(self):
        for slot in ('super:login-'+'a'*32, 'classify:ds@host:123', 'classify:ds', 'classify:typesafe'):
            with self.assertRaises(runtime.Failure):
                self.keys.reserve(slot)
        for mode in ('owner', 'attributes', 'ambiguous', 'delete', 'remaining'):
            self.setUp()
            slot = 'classify:last-backend'
            self.keys.reserve(slot)
            item = self.item(slot)
            if mode == 'owner':
                self.keys.current_owner.return_value = ('other-name',)
            elif mode == 'attributes':
                item.get_attributes.return_value['application'] = 'other-app'
            elif mode == 'ambiguous':
                self.item(slot)
            elif mode == 'delete':
                item.delete.side_effect = RuntimeError('secret backend error')
            else:
                item.delete.side_effect = None
            self.assertFalse(self.keys.cleanup(), mode)
            if mode in ('owner', 'attributes', 'ambiguous'):
                item.delete.assert_not_called()

    def test_private_constructor_rejects_untrusted_environment_before_native_import(self):
        with patch.dict(os.environ, {}, clear=True):
            for env in ({}, {'RSRS_SS_FIXTURE_BUS': 'private', 'DBUS_SESSION_BUS_ADDRESS': BUS}):
                with self.assertRaisesRegex(runtime.Failure, '^private_runtime_fixture_bus_required$'):
                    runtime.RuntimeProviderKeys(env)

    def test_constructor_requires_empty_unlocked_collection(self):
        for locked, occupied in ((False, False), (True, False), (False, True)):
            secretstorage, jeepney = Mock(), Mock()
            collection = secretstorage.get_collection_by_alias.return_value
            collection.is_locked.return_value = locked
            collection.get_all_items.return_value = [Mock()] if occupied else []
            secretstorage.dbus_init.return_value.send_and_get_reply.return_value.body = (':1.42',)
            env = {'RSRS_SS_FIXTURE_BUS': 'private', 'DBUS_SESSION_BUS_ADDRESS': BUS}
            with patch.dict(os.environ, env, clear=True), patch.object(runtime.sys, 'platform', 'linux'), \
                 patch.dict('sys.modules', {'secretstorage': secretstorage, 'jeepney': jeepney}):
                if locked or occupied:
                    with self.assertRaisesRegex(runtime.Failure, '^runtime_fixture_collection_not_empty_or_locked$'):
                        runtime.RuntimeProviderKeys(env)
                else:
                    keys = runtime.RuntimeProviderKeys(env)
                    self.assertEqual(keys.slots, set())
                    self.assertEqual(keys.owner, (':1.42',))
                collection.search_items.assert_not_called()

    def test_partial_reservation_failure_cleans_only_previously_owned_slots(self):
        self.keys.reserve('classify:last-backend')
        owned = self.item('classify:last-backend')
        collision = self.item('classify:ds-last-base')
        with self.assertRaises(runtime.Failure):
            self.keys.reserve('classify:ds-last-base')
        self.assertTrue(self.keys.cleanup())
        owned.delete.assert_called_once()
        collision.delete.assert_not_called()

    def test_child_teardown_errors_still_attempt_credential_cleanup_and_fail(self):
        for mode in ('terminate', 'kill', 'wait'):
            smoke = runtime.Smoke.__new__(runtime.Smoke)
            smoke.stop, smoke.child, smoke.attempted = Mock(), Mock(), False
            smoke.child.poll.return_value = None
            smoke.cloud_clean, smoke.provider_clean, smoke.report = True, True, {}
            smoke.provider_keys = Mock()
            smoke.provider_keys.cleanup.return_value = True
            if mode == 'terminate':
                smoke.child.terminate.side_effect = ProcessLookupError('secret-sentinel')
            else:
                smoke.child.wait.side_effect = runtime.subprocess.TimeoutExpired('secret-sentinel', 5)
                if mode == 'kill':
                    smoke.child.kill.side_effect = ProcessLookupError('secret-sentinel')
            smoke.cleanup()
            smoke.provider_keys.cleanup.assert_called_once()
            self.assertFalse(smoke.cloud_clean)
            self.assertFalse(smoke.report['cloud_cleanup']['passed'])
            self.assertTrue(smoke.report['provider_credential_cleanup']['passed'])
            self.assertNotIn('secret-sentinel', json.dumps(smoke.report))

    def test_cleanup_failure_fails_report_without_leaking_backend_exception(self):
        smoke = runtime.Smoke.__new__(runtime.Smoke)
        smoke.stop, smoke.child, smoke.attempted = Mock(), None, False
        smoke.cloud_clean, smoke.provider_clean, smoke.report = True, True, {}
        smoke.provider_keys = Mock()
        smoke.provider_keys.cleanup.side_effect = RuntimeError('secret-sentinel')
        smoke.cleanup()
        self.assertFalse(smoke.provider_clean)
        self.assertEqual(smoke.report['provider_credential_cleanup'], {'passed': False})
        self.assertNotIn('secret-sentinel', json.dumps(smoke.report))


class UnlockV2SourceTests(unittest.TestCase):
    """Source contract only; published-schema compilation and native delivery run in CI."""

    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]
        cls.sender = (cls.root / 'crates/client-host/src/host_credentials.rs').read_text(encoding='utf-8')
        cls.lifecycle = (cls.root / 'crates/host-control/src/lifecycle_io.rs').read_text(encoding='utf-8')
        cls.cli = (cls.root / 'cli/src/autostart/lifecycle.rs').read_text(encoding='utf-8')
        cls.unlock = cls.sender.split('pub fn unlock_runtime(', 1)[1].split('fn credential_backends(', 1)[0]

    def test_library_credentials_fail_before_optional_provider_collection(self):
        self.assertLess(self.unlock.index('read_session_credentials(&session)?'),
                        self.unlock.index('provider_credentials(installation, profile)'))
        self.assertLess(self.unlock.index('read_session_legacy_secret(&session)?'),
                        self.unlock.index('provider_credentials(installation, profile)'))
        self.assertIn('Runtime session key is unavailable; library remains locked', self.unlock)
        self.assertNotIn('keygen(', self.unlock)
        self.assertNotIn('return Ok(false)', self.unlock)

    def test_legacy_factor_requires_its_recorded_slot_without_disk_fallback(self):
        resolver = self.sender.split('fn read_session_legacy_secret(', 1)[1].split(
            'pub fn legacy_session_needs_migration(', 1)[0]
        self.assertIn('version != 1 && version != 3', resolver)
        self.assertIn('session["legacy_secret_backend"].as_str()', resolver)
        self.assertIn('session["keyring_account"].as_str()', resolver)
        self.assertIn('read_session_slot(&format!("legacy-secret:{account}"), backend)?', resolver)
        self.assertIn('explicit historical migration is required', resolver)
        self.assertIn('legacy secret credential is missing or empty', resolver)
        for source in (resolver, self.unlock):
            for field in ('session["secret"]', 'session["secret_key"]', 'session["keyring_backend"]'):
                self.assertNotIn(field, source)

    def test_v1_password_uses_ordinary_read_and_preserves_present_empty_values(self):
        slot = self.sender.split('fn read_session_slot(', 1)[1].split(
            'fn read_session_legacy_secret(', 1)[0]
        reader = self.sender.split('pub fn read_session_credentials(', 1)[1].split(
            'fn read_session_slot(', 1)[0]
        self.assertIn('operation: CredentialOperation::Read,', slot)
        self.assertIn('Ok(value) => Ok(value)', slot)
        self.assertIn('Err(CredentialError::NoEntry) => Ok(None)', slot)
        self.assertNotIn('.filter(', slot)
        self.assertIn('if version < 2 && slot == "pass"', reader)
        self.assertIn('read_session_slot(&format!("{slot}:{account}"), selected)?', reader)
        self.assertIn('slot == "super" || version < 2', reader)

    def test_delivery_is_v2_and_complete_or_explicitly_unavailable(self):
        self.assertIn('let input = RuntimeUnlockV2 {', self.unlock)
        self.assertIn('schema_version: RUNTIME_UNLOCK_SCHEMA_V2', self.unlock)
        self.assertNotIn('credentials::RuntimeUnlock {', self.unlock)
        self.assertIn('Ok(credentials) => ProviderCredentialUpdate::Replace { credentials }', self.unlock)
        self.assertIn('Err(code) => ProviderCredentialUpdate::Unavailable { code }', self.unlock)
        for code in ('AccessDenied', 'PlatformFailure', 'BackendUnavailable',
                     'InvalidConfiguration', 'Ambiguous', 'BadEncoding'):
            with self.subTest(code=code):
                self.assertIn('ProviderUnavailableCode::' + code, self.sender)
        for binding in ('session_sha256:', 'instance_id:', 'generation,', 'legacy_secret:'):
            self.assertIn(binding, self.unlock)
        self.assertIn('.redirects(0)', self.unlock)
        self.assertIn('.set("Authorization", &format!("Bearer {token}"))', self.unlock)

    def test_receipt_and_provider_outcome_are_required(self):
        self.assertIn('let receipt: RuntimeUnlockReceipt = reply.into_json()', self.unlock)
        self.assertIn('receipt.schema_version == RUNTIME_UNLOCK_SCHEMA_V2', self.unlock)
        self.assertIn('anyhow::ensure!(receipt.store_ready', self.unlock)
        self.assertIn('receipt.provider_status == expected_provider_status', self.unlock)
        self.assertIn('ureq::Error::Status(status, _)', self.unlock)
        self.assertIn('ureq::Error::Transport(error)', self.unlock)
        self.assertIn('provider credentials unavailable ({code:?})', self.unlock)
        for identity in ('health.installation_root', 'health.data_dir', 'health.instance_id',
                         'health.generation', 'health.process_start_id', 'health.image_sha256'):
            self.assertIn(identity, self.lifecycle)
        self.assertIn('Ok(supply_runtime_credentials(health)?.is_some())', self.lifecycle)
        self.assertIn('ProviderCredentialStatus::Unavailable { code } = receipt.provider_status', self.lifecycle)
        command = self.cli.split('RuntimeCommand::Unlock => {', 1)[1].split('RuntimeCommand::Autostart', 1)[0]
        self.assertIn('supply_runtime_credentials(&health)?', command)
        self.assertIn('"provider_status":receipt.provider_status', command)


if __name__ == '__main__':
    unittest.main()
