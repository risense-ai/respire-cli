import ast
import copy
import importlib.util
import json
from pathlib import Path
import unittest
import os
import subprocess
import sys
import tempfile

root = Path(__file__).parent
spec = importlib.util.spec_from_file_location("gate", root / "dev-smoke-gate.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class BusinessSummaryTests(unittest.TestCase):
    def setUp(self):
        self.mapping = json.loads((root / "dev-runtime-business-coverage.json").read_text())
        self.rows = [{"action": row["action"],
                      **({"removed_by_requirement": True} if row.get("removed_by_requirement") else {"passed": True})}
                     for row in self.mapping["actions"]]

    def test_current_contract_is_64_and_8(self):
        self.assertEqual(gate.business_summary(self.rows, self.mapping),
                         {"passed": True, "observed": 64, "removed_by_requirement": 8})

    def test_invalid_partition_and_counts_rejected(self):
        overlap = copy.deepcopy(self.rows)
        overlap[0]["removed_by_requirement"] = True
        missing = copy.deepcopy(self.rows)
        missing[0].pop("passed")
        wrong = dict(self.mapping, retained=66, removed_by_requirement=6)
        for rows, mapping in [(overlap, self.mapping), (missing, self.mapping),
                              (self.rows + [self.rows[0]], self.mapping), (self.rows[:-1], self.mapping),
                              (self.rows, wrong)]:
            with self.subTest(rows=len(rows), retained=mapping["retained"]):
                with self.assertRaises(RuntimeError):
                    gate.business_summary(rows, mapping)


class LoginContinuationSummaryTests(unittest.TestCase):
    def test_native_summary_requires_continuation_evidence_and_cleanup(self):
        tree = ast.parse((root / 'dev-smoke-gate.py').read_text())
        verify = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'verify')
        check = next(node for node in verify.body if isinstance(node, ast.If)
                     and ast.unparse(node.test) == "interruption.get('credential_mode') == 'secret_service'")
        code = compile(ast.Module(body=[check], type_ignores=[]), '<actual-continuation-summary>', 'exec')
        observation = {'passed': True, 'awaiting_input_observed': True, 'original_operation_committed': True,
                       'recovery_without_authentication_replay': True, 'distinct_transport_ids': True,
                       'repeated_material_unchanged': True, 'runtime_cleanup': {'passed': True}}
        key_observation = {'passed': True, 'awaiting_input_observed': True, 'source_super_only_deleted': True,
                           'original_operation_committed': True, 'distinct_transport_ids': True,
                           'reset_published_once': True, 'recovery_without_reset_replay': True,
                           'repeated_material_unchanged': True, 'new_super_decrypts_original_urk': True,
                           'post_reset_remember_recall': True, 'runtime_cleanup': {'passed': True}}
        native = {'credential_mode': 'secret_service', 'cases': {'host_login_continue': observation,
                                                               'host_key_continue': key_observation}}
        candidates = [(native, None), ({'credential_mode': 'headless', 'cases': {}}, None),
                      ({'credential_mode': 'secret_service', 'cases': {}}, 'login_continuation_case_missing')]
        for field in observation:
            incomplete = copy.deepcopy(native)
            incomplete['cases']['host_login_continue'].pop(field)
            candidates.append((incomplete, 'login_continuation_case_missing' if field == 'passed'
                               else 'login_continuation_not_proven'))
        no_key = copy.deepcopy(native)
        no_key['cases'].pop('host_key_continue')
        candidates.append((no_key, 'key_continuation_case_missing'))
        for field in key_observation:
            for wrong in (None, False):
                incomplete = copy.deepcopy(native)
                incomplete['cases']['host_key_continue'][field] = wrong
                if field == 'runtime_cleanup':
                    incomplete['cases']['host_key_continue'][field] = {'passed': wrong}
                candidates.append((incomplete, 'key_continuation_case_missing' if field == 'passed'
                                   else 'key_continuation_not_proven'))
        for report, error in candidates:
            with self.subTest(report=report, error=error):
                result = {'components': {'login_interruption': {'passed': True, 'required_observed': 3}}}
                scope = dict(interruption=report, result=result, require=gate.require, cases=gate.cases)
                if error:
                    with self.assertRaisesRegex(RuntimeError, error):
                        exec(code, scope)
                else:
                    exec(code, scope)
                    self.assertEqual(result['components']['login_interruption']['required_observed'],
                                     5 if report['credential_mode'] == 'secret_service' else 3)


class MigrationJoinReportTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="migration-join-gate-")
        self.addCleanup(self.directory.cleanup)
        self.folder = Path(self.directory.name)
        self.source = "a" * 40
        self.digest = "b" * 64
        self.version = "1.2.3-dev.4"
        supplements = sorted(gate.SUPPLEMENTS)
        self.base = {"source_sha": self.source, "observed_version": self.version,
                     "expected_version": self.version, "binary_sha256": self.digest,
                     "server": "https://api-dev.rsrs.rs", "base_complete": True,
                     "failed": 0, "required_missing": [], "supplemental_required": supplements,
                     "catalog": {"required_remaining": [], "supplemental_required": supplements,
                                 "required_assertions": ["synthetic-base-case"]},
                     "cases": [{"case": "synthetic-base-case", "result": "passed", "status": "ok"}],
                     "cloud_cleanup": {"passed": True, "remaining_users": []}}
        self.migration = {"source_sha": self.source, "version": self.version,
                          "binary_sha256": self.digest, "required_cases": sorted(gate.MIGRATION),
                          "passed": True, "missing_cases": [],
                          "cases": {name: {"passed": True} for name in gate.MIGRATION},
                          "cloud_cleanup": {"passed": True, "remaining_users": []},
                          "keyring_cleanup": {"passed": True, "remaining_entries": []},
                          "platform": sys.platform,
                          "keyring_backend": {"linux": "linux-keyutils", "darwin": "macos-keychain-synthetic-acl",
                                              "win32": "windows-credential-manager"}[sys.platform]}

    def run_gate(self, base, migration):
        for name, value in (("base.json", base), ("migration.json", migration)):
            (self.folder / name).write_text(json.dumps(value))
        report = self.folder / "joined.json"
        env = {key: value for key, value in os.environ.items()
               if not any(word in key.upper() for word in ("TOKEN", "SECRET", "PASSWORD"))}
        env["GITHUB_ACTIONS"] = "true"
        completed = subprocess.run([sys.executable, str(root / "dev-smoke-gate.py"), "--migration-only",
                                    "--cli-report", str(self.folder / "base.json"),
                                    "--profile-migration", str(self.folder / "migration.json"),
                                    "--report", str(report), "--source-sha", self.source,
                                    "--version", self.version, "--binary-sha256", self.digest],
                                   env=env, capture_output=True, text=True, timeout=10)
        return completed, json.loads(report.read_text())

    def test_actual_cli_joins_matching_report_files(self):
        completed, report = self.run_gate(self.base, self.migration)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertTrue(report["complete"])
        self.assertTrue(report["components"]["cli"]["passed"])
        self.assertTrue(report["components"]["profile_migration"]["passed"])
        extra = 'secret_service_current_credentials_for_legacy_db'
        secret_service = copy.deepcopy(self.migration)
        secret_service.update(platform='linux', keyring_backend='linux-secret-service',
                              required_cases=sorted(gate.MIGRATION | {extra}))
        for old_host_proof in (False, True):
            evidence = dict(passed=True, backend='secret_service')
            if old_host_proof:
                evidence.update(original_attributes_and_values_preserved=True,
                                legacy_services=['1memory', 'memocap', 'respire'])
            else:
                evidence.update(current_source_credentials_preserved=True,
                                database_origins=['1memory', 'memocap', 'respire'])
            secret_service['cases'][extra] = evidence
            source, output = self.folder / 'ss-source.json', self.folder / 'ss-result.json'
            source.write_text(json.dumps(secret_service), encoding='utf-8')
            result = subprocess.run([sys.executable, str(root / 'dev-secret-service-migration-gate.py'),
                '--migration-report', str(source), '--report', str(output), '--source-sha', self.source,
                '--version', self.version, '--binary-sha256', self.digest], capture_output=True, timeout=10)
            self.assertEqual(result.returncode, int(old_host_proof))
            self.assertEqual(json.loads(output.read_text())['passed'], not old_host_proof)

    def test_actual_cli_rejects_mixed_source_version_binary_and_incomplete_reports(self):
        for component, field, wrong, code in (
                ("base", "source_sha", "f" * 40, "artifact_source_mismatch"),
                ("migration", "source_sha", "f" * 40, "artifact_source_mismatch"),
                ("base", "binary_sha256", "f" * 64, "artifact_binary_mismatch"),
                ("migration", "binary_sha256", "f" * 64, "artifact_binary_mismatch"),
                ("base", "observed_version", "1.2.3-dev.3", "artifact_version_mismatch"),
                ("migration", "version", "1.2.3-dev.3", "artifact_version_mismatch"),
                ("migration", "passed", False, "migration_incomplete"),
                ("migration", "required_cases", sorted((gate.MIGRATION - {'explicit_dev_endpoint_preserved'}) |
                    {'legacy_api_defaults_rewritten'}), "migration_case_contract_mismatch"),
                ("migration", "cases", {name: {'passed': True} for name in gate.MIGRATION
                    if name != 'migration_wrong_key_rejected'}, "migration_required_cases_missing"),
                ("base", "base_complete", False, "cli_base_incomplete")):
            with self.subTest(component=component, field=field):
                base, migration = copy.deepcopy(self.base), copy.deepcopy(self.migration)
                (base if component == "base" else migration)[field] = wrong
                completed, report = self.run_gate(base, migration)
                self.assertNotEqual(completed.returncode, 0)
                self.assertFalse(report["complete"])
                self.assertEqual(report["failure_code"], code)


if __name__ == "__main__":
    unittest.main()
