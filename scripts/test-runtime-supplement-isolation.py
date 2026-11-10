"""Synthetic runner wiring; no native bus, services, binaries, or network."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('supplements', Path(__file__).with_name('dev-smoke-supplements.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class RunnerTests(unittest.TestCase):
    def run_fixture(self, platform='linux', runtime_exit=0, runtime_timeout=False):
        commands = []
        class Process:
            def __init__(self, argv, **kwargs):
                self.argv, self.calls, self.pid = argv, [], 987654321
                self.is_runtime = any(value.endswith('/dev-runtime-smoke.py') for value in argv)
                self.returncode = runtime_exit if self.is_runtime else 0
                commands.append(self)
            def communicate(self, timeout):
                self.calls.append(timeout)
                if self.is_runtime and runtime_timeout and len(self.calls) == 1:
                    raise subprocess.TimeoutExpired('synthetic', timeout)
                return b'', b''
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'supplements'
            args = ['fixture', '--binary', '/synthetic/cli', '--root', str(root), '--cli-report', '/synthetic/coverage',
                    '--binary-sha256', 'a'*64, '--version', 'test', '--source-sha', 'b'*40]
            with patch.dict(os.environ, {'RUNNER_TEMP': directory, 'GITHUB_ACTIONS': 'true',
                    'RUNNER_ENVIRONMENT': 'github-hosted', 'RSRS_SS_FIXTURE_BUS': 'private',
                    'DBUS_SESSION_BUS_ADDRESS': 'unix:path=/synthetic/shared'}, clear=True), \
                    patch.object(sys, 'argv', args), patch.object(sys, 'platform', platform), \
                    patch.object(module.subprocess, 'Popen', Process), \
                    patch.object(module.subprocess, 'run', return_value=SimpleNamespace(returncode=0)), \
                    patch.object(module.os, 'killpg') as kill:
                result = module.main()
                outcomes = json.loads((root / 'suite-results.json').read_text())
                kills = kill.call_count
            return result, commands, outcomes, kills

    def test_runtime_has_own_wrapper_and_business_deadline(self):
        result, processes, outcomes, kills = self.run_fixture()
        self.assertEqual(result, 0)
        for process in processes:
            if process.is_runtime:
                self.assertEqual(process.argv[:5], ['dbus-run-session', '--', 'env', 'RSRS_SS_FIXTURE_BUS=private', sys.executable])
                self.assertTrue(process.argv[5].endswith('/dev-secret-service-keyring-selftest.py'))
                self.assertTrue(process.argv[7].endswith('/runtime-credentials'))
                self.assertEqual(process.argv[8:11], ['--timeout', '1500', '--'])
                self.assertEqual(process.calls, [1800])
            else:
                self.assertFalse(any(value.endswith('/dev-secret-service-keyring-selftest.py') for value in process.argv))
                self.assertEqual(process.calls, [1500])
        self.assertEqual(len(outcomes), 6)
        self.assertEqual(kills, 0)

    def test_business_failure_and_outer_timeout_never_pass(self):
        for code, timeout in ((17, False), (0, True)):
            result, processes, outcomes, kills = self.run_fixture(runtime_exit=code, runtime_timeout=timeout)
            self.assertEqual(result, 1)
            outcome = next(row for row in outcomes if row['suite'] == 'runtime')
            self.assertFalse(outcome['passed'])
            if timeout:
                self.assertEqual(outcome['failure_code'], 'suite_timeout')
                self.assertEqual(kills, 1)
            else:
                self.assertEqual(outcome['exit'], code)

    def test_diagnostic_workflow_requires_private_wrapper_without_relaxing_scope(self):
        workflow = Path(__file__).resolve().parents[1] / '.github/workflows/dev-sweep.yml'
        text = workflow.read_text()
        block = text.split('      - name: Diagnose runtime contracts without a full release claim\n', 1)[1].split('      - name:', 1)[0]
        def contract(value):
            self.assertIn('inputs.local_api_only', value)
            self.assertIn("steps.native_credentials.outcome == 'success'", value)
            self.assertIn('dbus-run-session -- env RSRS_SS_FIXTURE_BUS=private python3 scripts/dev-secret-service-keyring-selftest.py --root "$RUNNER_TEMP/runtime-diagnostic-credentials" --timeout 1500 -- python3 scripts/dev-runtime-smoke.py', value)
            self.assertIn('--report "$RUNNER_TEMP/dev-supplements/runtime-coverage.json"', value)
        contract(block)
        for old, new in [('dbus-run-session -- ', ''), ('RSRS_SS_FIXTURE_BUS=private', 'RSRS_SS_FIXTURE_BUS=host'),
                         ('--timeout 1500', '--timeout 0'), ('runtime-diagnostic-credentials', 'supplement-credentials'),
                         ('inputs.local_api_only', 'true'), ("steps.native_credentials.outcome == 'success'", 'true')]:
            with self.assertRaises(AssertionError):
                contract(block.replace(old, new))

    def test_nonlinux_unmodified(self):
        result, processes, _, _ = self.run_fixture(platform='darwin')
        self.assertEqual(result, 0)
        self.assertTrue(all(process.argv[0] == sys.executable and process.calls == [1500] for process in processes))


if __name__ == '__main__':
    unittest.main()
