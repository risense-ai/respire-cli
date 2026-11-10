"""Offline predicate/redaction checks; no product process launches."""
import importlib.util
import itertools
import json
from pathlib import Path
import types
import unittest

spec = importlib.util.spec_from_file_location('runtime_smoke', Path(__file__).with_name('dev-runtime-smoke.py'))
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)
SECRET = '/private/user/token-secret'


class ClientOnlyTests(unittest.TestCase):
    def test_each_combined_gate_predicate_remains_mandatory(self):
        names = ['command_rejected', 'home_files_unchanged', 'profile_absent', 'endpoint_absent']
        for flags in itertools.product((False, True), repeat=4):
            result = types.SimpleNamespace(returncode=1 if flags[0] else 0, stdout=SECRET, stderr=SECRET)
            before = {SECRET: SECRET}
            after = before if flags[1] else {SECRET + '-new': SECRET}
            diagnostic = runtime.client_only_diagnostic(result, before, after, not flags[2], not flags[3])
            self.assertEqual(diagnostic['failed_checks'], [name for name, passed in zip(names, flags) if not passed])
            self.assertNotIn(SECRET, json.dumps(diagnostic))
            self.assertEqual(diagnostic['case_id'], 'client_only_no_profile_writes')

    def test_bad_exit_types_are_not_accepted_or_leaked(self):
        for code in (True, None, SECRET, {'secret': SECRET}):
            result = types.SimpleNamespace(returncode=code)
            diagnostic = runtime.client_only_diagnostic(result, {}, {}, False, False)
            self.assertIsNone(diagnostic['actual_exit'])
            self.assertEqual(diagnostic['failed_checks'], ['command_rejected'])
            self.assertNotIn(SECRET, json.dumps(diagnostic))

    def test_product_logging_initialization_remains_host_only(self):
        text = Path(__file__).parents[1].joinpath('cli/src/frontend.rs').read_text()
        body = text.split('fn prepare_command_runtime()', 1)[1].split('/// Point the error log', 1)[0]
        self.assertIn('if !runtime_policy::client_only() {', body)
        self.assertIn('        install_error_logging();\n    }\n    Ok(())', body)
        self.assertNotIn('    }\n    install_error_logging();', body)


if __name__ == '__main__':
    unittest.main()
