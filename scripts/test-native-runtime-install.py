"""Offline fixture installation tests; no credentials, downloads or live processes."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

from native_fixture_process import install_official_runtime


class FixtureInstallationTests(unittest.TestCase):
    def run_fixture(self, fault=None):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'fixture'
            root.mkdir()
            version, triple = '1.0.21-dev.17', 'synthetic-target'
            image = b'synthetic Runtime; never executed'
            digest = hashlib.sha256(image).hexdigest()
            env = {'RSRS_DATA_DIR': str(root), 'RSRS_RUNTIME_TRIPLE': triple,
                   'RSRS_RUNTIME_BIN': '/external/runtime', 'GH_TOKEN': 'not-real',
                   'GITHUB_TOKEN': 'not-real', 'RSRS_CORE_TEST_MODE': '1'}
            metadata = {'schema_version': 2, 'runtime_version': version,
                        'target_triple': triple, 'binary_sha256': digest}
            installed = root / 'runtime' / version / ('rsrs-runtime.exe' if os.name == 'nt' else 'rsrs-runtime')

            def installer(command, **kwargs):
                self.assertEqual(command, ['fixture-cli', '--json', 'runtime', 'install'])
                for key in ('RSRS_RUNTIME_BIN', 'RSRS_CORE_TEST_MODE', 'GH_TOKEN', 'GITHUB_TOKEN'):
                    self.assertNotIn(key, kwargs['env'])
                self.assertEqual(kwargs['env']['RSRS_DATA_DIR'], str(root))
                if fault == 'exit':
                    return types.SimpleNamespace(returncode=1)
                installed.parent.mkdir(parents=True)
                installed.write_bytes(b'corrupt' if fault == 'image' else image)
                if fault == 'target':
                    metadata['target_triple'] = 'wrong-target'
                encoded = json.dumps(metadata)
                proof = {'metadata_json': encoded,
                         'metadata_sha256': hashlib.sha256(encoded.encode()).hexdigest()}
                if fault == 'proof':
                    proof['metadata_sha256'] = '0' * 64
                receipt = {'version': version, 'sha256': digest, 'release': proof}
                if fault == 'version':
                    receipt['version'] = '1.0.21-dev.16'
                (root / 'runtime.json').write_text(json.dumps(receipt))
                return types.SimpleNamespace(returncode=0)

            if fault == 'existing':
                (root / 'runtime.json').write_text('{}')
            hosted = {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted',
                      'RUNNER_TEMP': temporary}
            if fault == 'host':
                hosted['RUNNER_ENVIRONMENT'] = 'self-hosted'
            if fault == 'outside':
                hosted['RUNNER_TEMP'] = str(root)
            with patch.dict(os.environ, hosted, clear=True), patch('subprocess.run', side_effect=installer) as run:
                if fault:
                    with self.assertRaises((ValueError, RuntimeError)):
                        install_official_runtime('fixture-cli', env, version, digest)
                    self.assertEqual(env['RSRS_RUNTIME_BIN'], '/external/runtime')
                    if fault in ('host', 'outside', 'existing'):
                        run.assert_not_called()
                else:
                    result = install_official_runtime('fixture-cli', env, version, digest)
                    self.assertEqual(result, installed.resolve())
                    self.assertEqual(env['RSRS_RUNTIME_BIN'], str(result))
                    run.assert_called_once()

    def test_fixture_receives_its_own_verified_installation(self):
        self.run_fixture()

    def test_invalid_installation_never_rebinds_runtime(self):
        for fault in ('exit', 'image', 'target', 'proof', 'version', 'existing', 'host', 'outside'):
            with self.subTest(fault=fault):
                self.run_fixture(fault)


if __name__ == '__main__':
    unittest.main()
