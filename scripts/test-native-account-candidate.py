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

    def save_core(self):
        candidate.write_json(self.staged / "core-runtime.json", self.core)

    def package(self):
        return candidate.package_runtime(self.runtime, self.staged, self.root / "archive",
            "1.0.21-dev.16", "a" * 40, "b" * 40, "c" * 64, "1.0.21-dev.5")

    def install_synthetic_receipt(self):
        archive, metadata_path = self.package()
        metadata = json.loads(metadata_path.read_text())
        installed = self.root / "installation/runtime/1.0.21-dev.16"
        installed.mkdir(parents=True)
        with tarfile.open(archive) as stream:
            stream.extractall(installed, filter="data")
        (installed / metadata["binary_file"]).rename(installed / "rsrs-runtime")
        candidate.write_json(self.root / "installation/runtime.json", {
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
        receipt_path = self.root / "installation/runtime.json"
        original = json.loads(receipt_path.read_text())
        for change in ("version", "sha256", "metadata_json", "metadata_sha256"):
            changed = copy.deepcopy(original)
            destination = changed["release"] if change.startswith("metadata_") else changed
            destination[change] = "different"
            candidate.write_json(receipt_path, changed)
            with self.subTest(change=change), self.assertRaisesRegex(RuntimeError, "offline_receipt_mismatch"):
                candidate.verify_receipt(self.root / "installation", metadata_path)

    def test_full_suite_requires_every_original_module_and_unique_case(self):
        names = [f"{module}::case_{index}" for module, count in candidate.MODULE_COUNTS.items()
                 for index in range(count)]
        names[names.index("account::case_0")] = candidate.CASE
        listing = "\n".join(name + ": test" for name in names)
        self.assertEqual(candidate.selected_cases(listing, "account"), [candidate.CASE])
        self.assertEqual(candidate.selected_cases(listing, "full"), names)
        for broken in (names[:-1], names + [names[0]],
                       ["unassigned::case_0" if name == names[0] else name for name in names]):
            with self.subTest(broken=broken), self.assertRaises(RuntimeError):
                candidate.selected_cases("\n".join(name + ": test" for name in broken), "full")
        with self.assertRaisesRegex(RuntimeError, "unknown_business_suite"):
            candidate.selected_cases(listing, "unknown")

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
