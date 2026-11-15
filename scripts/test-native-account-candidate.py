#!/usr/bin/env python3
"""Pure candidate fixture tests: no daemon, network, accounts, or executable runs."""
import copy
import gzip
import importlib.util
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

spec = importlib.util.spec_from_file_location("candidate", Path(__file__).with_name("native-account-candidate.py"))
candidate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(candidate)


class CandidateFixtureTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.staged = self.root / "stage"
        self.staged.mkdir()
        self.runtime = self.staged / "rsrs-runtime"
        self.runtime.write_bytes(b"synthetic bytes never executed")
        (self.staged / "lib").mkdir()
        resource = self.staged / "lib/libcore.so"
        resource.write_bytes(b"synthetic sdk payload")
        self.core = {"schema_version": 1, "target": candidate.TARGET, "files": [
            {"path": "lib/libcore.so", "size": resource.stat().st_size,
             "sha256": candidate.digest(resource)}]}
        self.save_core()

    def test_standalone_stop_requires_real_identity_outcomes_and_exports_only_scalars(self):
        identity = dict(image_sha256="a" * 64, installation_id="installation", instance_id="instance",
                        account_id="account", generation=1)
        common = dict(schema=1, evidence_class="native-raw", gate="not-evaluated", startup_mode="standalone",
                      runtime_identity=identity, accepted=dict(operation_id="stop", state="accepted"),
                      business_before_stop_ms=4201, business_held_after_stop_ms=4202,
                      provider_requests=1, provider_http_status=401, same_key_result=dict(code="request_in_progress"),
                      final_receipt=dict(identity, operation_id="stop", state="drained", unfinished=[]),
                      unused_private_text="must-never-be-exported")
        normal = dict(common, forced=False, passed=True, force_requests=[],
                      stale_scope_result=dict(code="scope_mismatch"), restarted_receipt=dict(state="drained"))
        forced = copy.deepcopy(normal)
        forced.update(forced=True, business_result=dict(operation_id="write"),
                      held_health=dict(inference=dict(retired_worker=dict(worker_reaped=True))),
                      force_requests=[dict(operation_id="stop", timeout_state="forced_timeout")])
        forced["final_receipt"].update(state="forced_timeout", unfinished=[dict(operation_id="write", result="unknown")])
        write = dict(common, provider_http_status=200, encrypted_write_committed=True,
                     plaintext_parent_matches_encrypted_payload=True)
        rows = [normal, forced, write]
        def captured(values):
            return b"\n".join(marker + json.dumps(row).encode() for marker, row in zip(
                (b"NATIVE_STOP_RAW ", b"NATIVE_STOP_RAW ", b"NATIVE_ACCEPTED_WRITE_RAW "), values))
        report = candidate.standalone_stop_checks(captured(rows), "a" * 64)
        self.assertTrue(report["passed"])
        self.assertEqual({row["case"] for row in report["observations"]},
                         {"normal", "explicit-force", "accepted-write"})
        self.assertNotIn("must-never-be-exported", json.dumps(report))
        for index, key, value in [(0, "runtime_identity", dict(identity, image_sha256="b" * 64)),
                                  (0, "business_held_after_stop_ms", 4000),
                                  (1, "forced", False), (1, "force_requests", []),
                                  (1, "held_health", dict(inference=dict(retired_worker=dict(worker_reaped=False)))),
                                  (2, "encrypted_write_committed", False),
                                  (2, "provider_requests", 2)]:
            broken = copy.deepcopy(rows)
            broken[index][key] = value
            with self.subTest(index=index, key=key), self.assertRaises(RuntimeError):
                candidate.standalone_stop_checks(captured(broken), "a" * 64)
        with self.assertRaisesRegex(RuntimeError, "standalone_stop_case_inventory_mismatch"):
            candidate.standalone_stop_checks(captured(rows[:2]), "a" * 64)

    def test_owned_stop_options_are_diagnostic_current_source_only(self):
        from types import SimpleNamespace
        options = dict(owned_stop_mode="registered", client2_source=Path("source"),
            cli_sha="a" * 40, runtime_sha="b" * 40,
            suite="diagnostic-native-stop", official_cli_metadata=None, legacy_stable_contracts=False,
            stable_business_cli=None, stable_business_cli_metadata=None, stable_business_runtime_archive=None,
            runtime_archive=None, runtime_metadata=None, require_native_stop=False)
        with patch.dict(os.environ, {"GITHUB_SHA": "a" * 40}):
            candidate.validate_owned_stop_options(SimpleNamespace(**options))
            for field, value in (("owned_stop_mode", "unknown"), ("suite", "full"),
                                 ("official_cli_metadata", Path("old.json")), ("client2_source", None),
                                 ("cli_sha", "c" * 40)):
                with self.subTest(field=field), self.assertRaises(RuntimeError):
                    candidate.validate_owned_stop_options(SimpleNamespace(**dict(options, **{field: value})))

    def test_owned_probe_is_built_from_fixed_sources_without_external_execution(self):
        import io
        from types import SimpleNamespace
        source = self.root / "source"
        source.mkdir()
        cli_source = self.root / "cli-source"
        fixture_dir = cli_source / "scripts/fixtures/client2-v0256-probe"
        fixture_dir.mkdir(parents=True)
        for name in candidate.OWNED_PROBE_FILES:
            (fixture_dir / name).write_bytes(b"package main\n")
        args = SimpleNamespace(owned_stop_mode="client2-owned", client2_source=source,
            cli_source=cli_source, cli_sha="a" * 40, runtime_sha="b" * 40,
            suite="diagnostic-native-stop", official_cli_metadata=None, legacy_stable_contracts=False,
            stable_business_cli=None, stable_business_cli_metadata=None, stable_business_runtime_archive=None,
            runtime_archive=None, runtime_metadata=None, require_native_stop=False)
        commands = []
        def fake_run(command, **kwargs):
            commands.append(command)
            if command[0] == "git":
                with tarfile.open(fileobj=kwargs["stdout"], mode="w") as archive:
                    content = b"synthetic dependency hashes never executed\n"
                    member = tarfile.TarInfo("go.sum")
                    member.size = len(content)
                    archive.addfile(member, io.BytesIO(content))
            else:
                self.assertEqual(command[:3], ["go", "build", "-buildvcs=false"])
                Path(command[command.index("-o") + 1]).write_bytes(b"synthetic probe never executed")
        with patch.dict(os.environ, {"GITHUB_SHA": "a" * 40}), \
             patch.object(candidate, "verify_source") as verify, \
             patch.object(candidate.subprocess, "check_output", return_value=b"package main\n"), \
             patch.object(candidate.subprocess, "run", side_effect=fake_run):
            binary, identity = candidate.build_owned_stop_probe(args, self.root, io.BytesIO())
        verify.assert_called_once_with(source.resolve(), candidate.CLIENT2_OWNED_SOURCE_SHA)
        self.assertEqual(identity["probe_binary_sha256"], candidate.digest(binary))
        self.assertEqual(len(identity["probe_fixture_sha256"]), 4)
        self.assertEqual(commands[0][-1], candidate.CLIENT2_OWNED_SOURCE_SHA)
        self.assertEqual(len(commands), 2)

    def test_owned_stop_rejects_wrong_probe_or_missing_real_mode(self):
        rows = []
        for case in ("normal", "caller-timeout", "explicit-force"):
            rows.append(dict(case=case, startup_mode="client2-owned", passed=True, probe_sha256="a" * 64,
                business_sender="modern-harness", stop_sender="original-go-client2",
                caller_timeout_ms=None if case == "normal" else 35000,
                provider_http_status=200, provider_requests=1,
                credential_cleanup_verified=True, runtime_compatibility_timeout_claimed=False,
                runtime_identity={"image_sha256": "b" * 64},
                encrypted_write_committed=case != "explicit-force",
                forced_operation_remains_unknown=case == "explicit-force"))
        captured = b"\n".join(b"NATIVE_CLIENT2_STOP_RAW " + json.dumps(row).encode() for row in rows)
        self.assertEqual(len(candidate.owned_stop_checks(captured, "client2-owned", "a" * 64, "b" * 64)), 3)
        with self.assertRaises(RuntimeError):
            candidate.owned_stop_checks(captured, "client2-owned", "c" * 64, "b" * 64)
        with self.assertRaises(RuntimeError):
            candidate.owned_stop_checks(captured, "registered", "a" * 64, "b" * 64)
        for field, value in (("stop_sender", "private-canary"), ("caller_timeout_ms", "private-canary"),
                             ("caller_timeout_ms", True), ("caller_timeout_ms", 29999)):
            invalid = [dict(row) for row in rows]
            invalid[1][field] = value
            payload = b"\n".join(b"NATIVE_CLIENT2_STOP_RAW " + json.dumps(row).encode() for row in invalid)
            with self.subTest(field=field, value=value), self.assertRaises(RuntimeError):
                candidate.owned_stop_checks(payload, "client2-owned", "a" * 64, "b" * 64)

    def test_owned_failure_stages_are_bounded_and_never_publish_private_fields(self):
        def captured(events):
            return (b"failures:\n---- " + candidate.NATIVE_STOP_CASE.encode() + b" stdout ----\n"
                    + b"\n".join(b"OWNED_STOP_CHECKPOINT " + json.dumps(event).encode() for event in events))
        event = {"startup_mode": "client2-owned", "case": "normal", "stage": "start_requested"}
        result = candidate.safe_failure_diagnostics(captured([event]), [candidate.NATIVE_STOP_CASE])
        self.assertEqual(result["owned_stop_checkpoints"], [event])
        self.assertFalse(result["owned_stop_checkpoint_invalid"])
        for invalid in ({**event, "stage": "private-canary"}, {**event, "case": "private-canary"},
                        {**event, "startup_mode": "private-canary"}, {**event, "secret": "private-canary"},
                        {**event, "stage": ["private-canary"]}, {**event, "stage": "private-canary" * 300}):
            result = candidate.safe_failure_diagnostics(captured([invalid]), [candidate.NATIVE_STOP_CASE])
            self.assertTrue(result["owned_stop_checkpoint_invalid"])
            self.assertEqual(result["owned_stop_checkpoints"], [])
            self.assertNotIn("private-canary", json.dumps(result))
        result = candidate.safe_failure_diagnostics(captured([event] * 129), [candidate.NATIVE_STOP_CASE])
        self.assertTrue(result["owned_stop_checkpoint_invalid"])
        self.assertEqual(len(result["owned_stop_checkpoints"]), 128)
        ignored = candidate.safe_failure_diagnostics(captured([event]), [])
        self.assertEqual(ignored["owned_stop_checkpoints"], [])
        for message, expected in (
                ("systemd user session unavailable", "owned_registered_systemd_unavailable"),
                ("systemd unit load state is unavailable or unexpected", "owned_registered_systemd_load_state_invalid"),
                ("systemd unit path missing", "owned_registered_systemd_unit_path_missing"),
                ("unknown systemd user unit path", "owned_registered_systemd_unit_path_mismatch"),
                ("systemd loaded working directory differs from this installation", "owned_registered_systemd_working_directory_mismatch"),
                ("systemd unit object unavailable", "owned_registered_systemd_unit_object_missing"),
                ("unexpected systemd unit object", "owned_registered_systemd_unit_object_invalid"),
                ("systemctl current-user operation failed", "owned_registered_systemctl_failed"),
                ("busctl current-user operation failed", "owned_registered_busctl_failed")):
            private = captured([event]) + b"\n" + message.encode() + b" private-canary\n"
            result = candidate.safe_failure_diagnostics(private, [candidate.NATIVE_STOP_CASE])
            with self.subTest(message=message):
                self.assertEqual(result["failure_codes"][candidate.NATIVE_STOP_CASE], [expected])
                self.assertNotIn("private-canary", json.dumps(result))
        private = captured([event]) + b"\nREGISTERED_LIFECYCLE_ERROR private-canary\n"
        result = candidate.safe_failure_diagnostics(private, [candidate.NATIVE_STOP_CASE])
        self.assertEqual(result["failure_codes"][candidate.NATIVE_STOP_CASE], ["unknown_private_failure"])
        self.assertNotIn("private-canary", json.dumps(result))

    def test_login_receipt_failure_reports_only_fixed_code(self):
        captured = (b"failures:\n---- " + candidate.CASE.encode() + b" stdout ----\n"
            b"Error: login session does not match its committed credential receipt\n"
            b"private-credential-must-not-be-exported\n")
        result = candidate.safe_failure_diagnostics(captured, [candidate.CASE])
        self.assertEqual(result["failure_codes"][candidate.CASE], ["account_login_receipt_mismatch"])
        self.assertNotIn("private-credential-must-not-be-exported", json.dumps(result))
        outside = (b"Error: trailing characters at line 2 column 1 private-value\n"
            b"failures:\n---- " + candidate.CASE.encode() + b" stdout ----\n"
            b"account-checkpoint oauth_completed\naccount-checkpoint private-value\n")
        result = candidate.safe_failure_diagnostics(outside, [candidate.CASE])
        self.assertEqual(result["failure_codes"][candidate.CASE], ["account_json_trailing_data"])
        self.assertEqual(result["account_checkpoints"], ["oauth_completed"])
        self.assertNotIn("private-value", json.dumps(result))
        unrelated = candidate.safe_failure_diagnostics(outside, [candidate.CASE, "other::case"])
        self.assertNotIn("account_json_trailing_data", unrelated["failure_codes"][candidate.CASE])

    def test_account_error_sources_do_not_echo_private_output(self):
        message = b"target Runtime does not match the selected account, image or managed owner"
        captured = (b"failures:\n---- " + candidate.CASE.encode() + b" stdout ----\n"
                    + message + b" private-canary\n")
        result = candidate.safe_failure_diagnostics(captured, [candidate.CASE])
        locations = result["host_error_sources"][candidate.CASE]
        self.assertTrue(any(item["file"] == "crates/host-control/src/maintenance.rs" for item in locations))
        self.assertTrue(all(set(item) == {"file", "line"} and item["line"] > 0 for item in locations))
        self.assertNotIn("private-canary", json.dumps(result))
        self.assertEqual(candidate.safe_failure_diagnostics(captured, [])["host_error_sources"], {})

    def save_core(self):
        candidate.write_json(self.staged / "core-runtime.json", self.core)

    def package(self):
        return candidate.package_runtime(self.runtime, self.staged, self.root / "archive",
            "1.0.21-dev.16", "a" * 40, "b" * 40, "c" * 64, "1.0.21-dev.5")

    def install_synthetic_receipt(self):
        archive, metadata_path = self.package()
        metadata = json.loads(metadata_path.read_text())
        installed = self.root / "installation/bin/runtime/1.0.21-dev.16"
        installed.mkdir(parents=True)
        with tarfile.open(archive) as stream:
            stream.extractall(installed, filter="data")
        (installed / metadata["binary_file"]).rename(installed / "rsrs-runtime")
        candidate.write_json(self.root / "installation/bin/runtime.json", {
            "version": "1.0.21-dev.16", "sha256": candidate.digest(self.runtime),
            "release": {"metadata_json": metadata_path.read_text(),
                        "metadata_sha256": candidate.digest(metadata_path)}})
        return metadata_path, installed

    def test_complete_unpublished_archive(self):
        archive, metadata_path = self.package()
        metadata = json.loads(metadata_path.read_text())
        self.assertEqual(metadata["candidate"], {"kind": "unpublished-source-fixture",
            "cli_source_sha": "b" * 40, "cli_binary_sha256": "c" * 64})
        self.assertEqual(metadata["source_commit"], "a" * 40)
        self.assertEqual(metadata["runtime_version"], "1.0.21-dev.16")
        self.assertEqual(metadata["archive_sha256"], candidate.digest(archive))
        raw = gzip.decompress(archive.read_bytes())
        offset = 0
        while raw[offset:offset + 512] != bytes(512):
            header = raw[offset:offset + 512]
            self.assertEqual(header[257:262], b"ustar")
            self.assertEqual(header[156:157], b"0", "Product rejects PAX/GNU extension headers")
            size = int(header[124:136].strip(b" \0"), 8)
            offset += 512 + ((size + 511) // 512) * 512
        self.assertEqual(raw[offset:], bytes(len(raw) - offset))
        with tarfile.open(archive) as stream:
            self.assertEqual(sorted(stream.getnames()), sorted(row["path"] for row in metadata["files"]))
            self.assertTrue(all(entry.isfile() for entry in stream.getmembers()))

    def test_path_rejections(self):
        for path in ("", "../escape", "/tmp/escape", "lib/../core", "lib//core", "lib\\core", "lib:core", "lib/\0"):
            with self.subTest(path=path), self.assertRaises(RuntimeError):
                candidate.safe_file(self.staged, path)

    def test_symlink_rejected(self):
        (self.staged / "link").symlink_to("lib", target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError, "linked_payload_rejected"):
            candidate.safe_file(self.staged, "link/libcore.so")

    def test_duplicate_rejected(self):
        self.core["files"] *= 2
        self.save_core()
        with self.assertRaisesRegex(RuntimeError, "duplicate_payload_path"):
            self.package()

    def test_core_hash_rejected(self):
        (self.staged / "lib/libcore.so").write_bytes(b"changed")
        with self.assertRaisesRegex(RuntimeError, "staged_core_digest_mismatch"):
            self.package()

    def test_wrong_target_rejected(self):
        self.core["target"] = "aarch64-unknown-linux-gnu"
        self.save_core()
        with self.assertRaisesRegex(RuntimeError, "core_target_mismatch"):
            self.package()

    def test_exact_receipt_and_inventory(self):
        metadata_path, installed = self.install_synthetic_receipt()
        self.assertEqual(candidate.verify_receipt(self.root / "installation", metadata_path),
                         installed / "rsrs-runtime")
        (installed / "lib/libcore.so").write_bytes(b"tampered")
        with self.assertRaisesRegex(RuntimeError, "installed_inventory_mismatch"):
            candidate.verify_receipt(self.root / "installation", metadata_path)

    def test_receipt_metadata_cannot_be_rewritten(self):
        metadata_path, _ = self.install_synthetic_receipt()
        receipt_path = self.root / "installation/bin/runtime.json"
        original = json.loads(receipt_path.read_text())
        for change in ("version", "sha256", "metadata_json", "metadata_sha256"):
            changed = copy.deepcopy(original)
            destination = changed["release"] if change.startswith("metadata_") else changed
            destination[change] = "different"
            candidate.write_json(receipt_path, changed)
            with self.subTest(change=change), self.assertRaisesRegex(RuntimeError, "offline_receipt_mismatch"):
                candidate.verify_receipt(self.root / "installation", metadata_path)

    def test_full_suite_requires_every_original_module_and_unique_case(self):
        names = list(candidate.BASELINE_CASES)
        self.assertEqual(len(names), 30)
        listing = "\n".join(name + ": test" for name in names)
        self.assertEqual(candidate.selected_cases(listing, "account"), [candidate.CASE])
        with self.assertRaisesRegex(RuntimeError, "g1_business_case_inventory_mismatch"):
            candidate.selected_cases(listing, "g1-business")
        with self.assertRaisesRegex(RuntimeError, "original_account_case_missing"):
            candidate.selected_cases("\n".join(name + ": test" for name in names if name != candidate.CASE), "g1-business")
        self.assertEqual(candidate.selected_cases(listing, "full"), names)
        self.assertEqual(candidate.selected_cases(listing, "diagnostic-failures"), list(candidate.DIAGNOSTIC_CASES))
        extended = names + [candidate.NATIVE_STOP_CASE]
        extended_listing = "\n".join(name + ": test" for name in extended)
        self.assertEqual(candidate.selected_cases(extended_listing, "full"), extended)
        self.assertEqual(set(candidate.selected_cases(extended_listing, "g1-business")),
                         set(candidate.G1_BUSINESS_CASES))
        self.assertIn(candidate.CASE, candidate.G1_BUSINESS_CASES)
        self.assertIn(candidate.NATIVE_STOP_CASE, candidate.G1_BUSINESS_CASES)
        self.assertEqual(candidate.selected_cases(extended_listing, "full", True), extended)
        self.assertEqual(candidate.selected_cases(extended_listing, "diagnostic-native-stop"), [candidate.NATIVE_STOP_CASE])
        self.assertEqual(candidate.selected_cases(extended_listing, "g1-owned-stop"), [candidate.NATIVE_STOP_CASE])
        with self.assertRaisesRegex(RuntimeError, "native_stop_business_case_missing"):
            candidate.selected_cases(listing, "diagnostic-native-stop")
        with self.assertRaisesRegex(RuntimeError, "native_stop_business_case_missing"):
            candidate.selected_cases(extended_listing + "\n" + candidate.NATIVE_STOP_CASE + ": test", "diagnostic-native-stop")
        with self.assertRaisesRegex(RuntimeError, "native_stop_business_case_missing"):
            candidate.selected_cases(listing, "full", True)
        for suite in ("account", "diagnostic-failures", "diagnostic-native-stop"):
            with self.subTest(suite=suite), self.assertRaisesRegex(RuntimeError, "native_stop_requires_full_suite"):
                candidate.selected_cases(listing, suite, True)
        for broken in (names[:-1], names + [names[0]],
                       ["unassigned::case_0" if name == names[0] else name for name in names],
                       ["diary_identity::unknown_replacement" if name == names[5] else name for name in names],
                       names + ["diary_identity::unknown_addition"],
                       extended + [candidate.NATIVE_STOP_CASE]):
            with self.subTest(broken=broken), self.assertRaises(RuntimeError):
                candidate.selected_cases("\n".join(name + ": test" for name in broken), "full")
        with self.assertRaisesRegex(RuntimeError, "unknown_business_suite"):
            candidate.selected_cases(listing, "unknown")

    def test_frozen_owned_stop_requires_exact_runtime_workflow_and_original_package(self):
        args = SimpleNamespace(suite="g1-owned-stop", owned_stop_mode="registered",
            client2_source=self.root, cli_sha="a" * 40, runtime_sha="b" * 40,
            runtime_archive=self.root / "original.tar.gz", runtime_metadata=self.root / "original.json",
            official_cli_metadata=None, legacy_stable_contracts=False, require_native_stop=False,
            stable_business_cli=None, stable_business_cli_metadata=None, stable_business_runtime_archive=None)
        with patch.dict(os.environ, {"GITHUB_REPOSITORY": "risense-ai/respire-runtime",
                                     "GITHUB_SHA": args.runtime_sha}):
            for mode in ("registered", "client2-owned"):
                args.owned_stop_mode = mode
                candidate.validate_owned_stop_options(args)
            for key, value in (("owned_stop_mode", None), ("client2_source", None),
                               ("runtime_archive", None), ("runtime_metadata", None),
                               ("runtime_sha", "c" * 40), ("cli_sha", "main")):
                altered = copy.copy(args)
                setattr(altered, key, value)
                with self.subTest(key=key), self.assertRaises(RuntimeError):
                    candidate.validate_owned_stop_options(altered)
            for environment in ({"GITHUB_REPOSITORY": "risense-ai/respire-cli"},
                                {"GITHUB_SHA": args.cli_sha}):
                with patch.dict(os.environ, environment), self.assertRaises(RuntimeError):
                    candidate.validate_owned_stop_options(args)
        self.assertEqual(candidate.CLIENT2_OWNED_SOURCE_SHA, "6ffa187685734873721ab51f3a54d8b2c29cd269")

    def test_compatibility_host_checkpoints_do_not_publish_private_fields(self):
        checks = [{"stage": "space-profile", "passed": True},
                  {"stage": "import-target", "passed": False}]
        captured = b"private auth output never published\n" + b"\n".join(
            b"test prefix ... client2-account-host " + json.dumps(check).encode() for check in checks)
        self.assertEqual(candidate.compatibility_host_checks(captured), checks)
        self.assertEqual(candidate.compatibility_host_checks(b"unrelated private output"), [])
        for invalid in ({"stage": "space-profile", "passed": True, "secret": "private"},
                        {"stage": "private-value", "passed": True},
                        {"stage": "import-target", "passed": 1}):
            self.assertIsNone(candidate.compatibility_host_checks(
                b"client2-account-host " + json.dumps(invalid).encode()))
        self.assertIsNone(candidate.compatibility_host_checks(b"client2-account-host malformed"))

    def test_credentials_and_bus_not_inherited(self):
        ambient = {"PATH": "/bin", "CORE_SDK_READ_TOKEN": "secret", "GITHUB_TOKEN": "secret",
            "GH_TOKEN": "secret", "DBUS_SESSION_BUS_ADDRESS": "unix:old", "RSRS_SUPER": "secret",
            "HOME": "/old", "HTTP_PROXY": "https://old.invalid", "SSH_AUTH_SOCK": "/old"}
        with patch.dict(os.environ, ambient, clear=True):
            result = candidate.private_env(self.root)
        self.assertEqual(result["HOME"], str(self.root / "home"))
        self.assertEqual(result["TMPDIR"], str(self.root / "tmp"))
        self.assertFalse(any(key in result for key in ambient.keys() - {"PATH", "HOME"}))

    def test_private_command_does_not_retry_failure(self):
        process = MagicMock()
        child = process.__enter__.return_value
        child.wait.return_value = 17
        with patch.object(candidate.subprocess, "Popen", return_value=process) as start:
            with self.assertRaisesRegex(RuntimeError, "private_command_failed"):
                candidate.private_command(["fixture"], {}, self.root, None, 900)
        self.assertEqual(start.call_count, 1)
        self.assertEqual(child.wait.call_count, 1)
        self.assertTrue(start.call_args.kwargs["start_new_session"])

    def test_private_command_timeout_stops_owned_group_once(self):
        process = MagicMock()
        child = process.__enter__.return_value
        child.pid = 12345
        child.wait.side_effect = [candidate.subprocess.TimeoutExpired("fixture", 900), -9]
        with patch.object(candidate.subprocess, "Popen", return_value=process) as start:
            with patch.object(candidate.os, "killpg") as stop:
                with self.assertRaises(candidate.subprocess.TimeoutExpired):
                    candidate.private_command(["fixture"], {}, self.root, None, 900)
        self.assertEqual(start.call_count, 1)
        stop.assert_called_once_with(12345, candidate.signal.SIGKILL)

    def test_sha_parser_rejects_symbolic_sources(self):
        for sha in ("main", "a" * 39, "A" * 40, "a" * 40 + "\n"):
            with self.subTest(sha=sha), self.assertRaisesRegex(RuntimeError, "exact_source_sha_required"):
                candidate.verify_source(self.root, sha)


if __name__ == "__main__":
    unittest.main()
