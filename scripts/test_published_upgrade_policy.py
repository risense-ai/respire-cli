import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from published_upgrade_policy import platform_applicability, select_upgrade_sources


class UpgradePolicyTest(unittest.TestCase):
    def test_only_exact_documented_arm_gaps_are_not_applicable(self):
        for target in ["aarch64-unknown-linux-gnu", "aarch64-unknown-linux-musl", "aarch64-pc-windows-msvc"]:
            gaps = ["v1.0.15", "v1.0.16"]
            if "linux" in target:
                gaps.append("v1.0.17-dev.12")
            for tag in gaps:
                self.assertIsNotNone(platform_applicability(tag, target, []))
            for tag in ["v1.0.7", "v1.0.10", "v1.0.12", "v1.0.17", "v1.0.18"]:
                with self.assertRaises(ValueError):
                    platform_applicability(tag, target, [])

    def test_partial_or_non_arm_missing_assets_always_fail(self):
        target = "aarch64-unknown-linux-gnu"
        for asset in [f"rsrs-{target}", f"rsrs-{target}-runtime.tar.gz", f"cli-build-{target}.json"]:
            with self.assertRaises(ValueError):
                platform_applicability("v1.0.16", target, [asset])
        with self.assertRaises(ValueError):
            platform_applicability("v1.0.16", "x86_64-unknown-linux-gnu", [])
        self.assertIsNotNone(platform_applicability("v1.0.19", "x86_64-apple-darwin", []))
        for tag, assets in [("v1.0.20", []), ("v1.0.19", ["rsrs-x86_64-apple-darwin"])]:
            with self.assertRaises(ValueError):
                platform_applicability(tag, "x86_64-apple-darwin", assets)

    def test_present_historical_arm_assets_remain_required(self):
        target = "aarch64-unknown-linux-musl"
        assets = [f"rsrs-{target}", f"rsrs-{target}-runtime.tar.gz", f"cli-build-{target}.json"]
        for tag in ["v1.0.7", "v1.0.16"]:
            self.assertIsNone(platform_applicability(tag, target, assets))


class UpgradeProfileTest(unittest.TestCase):
    target = "aarch64-unknown-linux-gnu"

    def release(self, tag, missing=False, draft=False, prerelease=False):
        names = [f"rsrs-{self.target}", f"rsrs-{self.target}-runtime.tar.gz", f"cli-build-{self.target}.json"]
        return {"tag_name": tag, "draft": draft, "prerelease": prerelease,
                "assets": [] if missing else [{"name": name} for name in names]}

    def test_critical_uses_numeric_version_order(self):
        releases = [self.release(tag) for tag in ["v1.0.9", "v1.0.18", "v1.0.10"]]
        sources = {release["tag_name"]: release for release in releases}
        self.assertEqual(list(select_upgrade_sources(sources, self.target, "critical")), ["v1.0.18"])
        self.assertEqual(select_upgrade_sources(sources, self.target, "full"), sources)

    def test_only_known_whole_platform_gaps_can_fall_back(self):
        sources = {tag: self.release(tag, missing=tag == "v1.0.16") for tag in ["v1.0.12", "v1.0.16"]}
        self.assertEqual(list(select_upgrade_sources(sources, self.target, "critical")), ["v1.0.12"])
        sources["v1.0.18"] = self.release("v1.0.18", missing=True)
        with self.assertRaisesRegex(ValueError, "missing platform artifact"):
            select_upgrade_sources(sources, self.target, "critical")

    def test_partial_latest_or_no_applicable_source_fails(self):
        self.assertEqual(select_upgrade_sources({"v1.0.19": {"assets": []}}, "x86_64-apple-darwin", "critical"), {})
        release = self.release("v1.0.16")
        release["assets"].pop()
        with self.assertRaisesRegex(ValueError, "missing platform artifact"):
            select_upgrade_sources({"v1.0.16": release}, self.target, "critical")
        for sources in [{}, {"v1.0.16": self.release("v1.0.16", missing=True)}]:
            with self.assertRaisesRegex(ValueError, "no applicable formal stable"):
                select_upgrade_sources(sources, self.target, "critical")

    def run_fixture(self, profile=None, missing_latest=False, registry=None, empty_checks=False,
                    checks_transform=None, standalone=False, standalone_mode="published-assets",
                    cache_draft=False, download_only=False, corrupt_draft=False):
        # Execute the real orchestration with local artifact bytes and a fake upgrade child.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate = root / "candidate"
            candidate.write_bytes(b"candidate")
            digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
            runtime = root / "standalone-runtime-not-executed"
            runtime.write_bytes(b"synthetic standalone artifact")
            runtime_digest = hashlib.sha256(runtime.read_bytes()).hexdigest()
            runtime_version = "synthetic-runtime-v1"
            archive = io.BytesIO()
            with tarfile.open(fileobj=archive, mode="w:gz"):
                pass
            releases = [self.release(tag, missing=missing_latest and tag == "v1.0.18")
                        for tag in ["v1.0.12", "v1.0.18", "v1.0.6-dev.37075716045"]]
            releases[-1]["prerelease"] = True
            releases.append(self.release("v1.0.10", draft=True))
            releases[-1]["id"] = 403872621
            files = {}
            for release in releases:
                tag = release["tag_name"]
                values = [b"old-binary", archive.getvalue()]
                values.append(json.dumps({"version": tag[1:], "target": self.target,
                    "binary_sha256": hashlib.sha256(values[0]).hexdigest(),
                    "runtime_sha256": hashlib.sha256(values[1]).hexdigest()}).encode())
                for asset, value in zip(release["assets"], values):
                    asset.update(digest="sha256:" + hashlib.sha256(value).hexdigest(), id=len(files))
                    files[(tag, asset["name"])] = value
            def output(command, **kwargs):
                if command[0] == "npm":
                    return json.dumps(registry if registry is not None else ["1.0.12", "1.0.18"])
                if command[-1].endswith("/403872621"):
                    self.assertFalse(cache_draft, "cached draft must not require authenticated metadata access")
                    return json.dumps(releases[-1])
                return json.dumps(releases)
            upgraded = []
            def run(command, **kwargs):
                if command[0] == "gh":
                    if command[1] == "api":
                        asset_id = int(command[2].rsplit("/", 1)[1])
                        kwargs["stdout"].write(next(value for release in releases for asset in release["assets"]
                            if asset["id"] == asset_id for value in [files[(release["tag_name"], asset["name"])]]))
                    else:
                        tag = command[3]
                        folder = Path(command[command.index("--dir") + 1])
                        for (source, name), value in files.items():
                            if source == tag:
                                (folder / name).write_bytes(value)
                else:
                    self.assertFalse(download_only, "download-only must never execute a product fixture")
                    if standalone:
                        self.assertEqual(command[command.index("--runtime-binary") + 1], str(runtime))
                        self.assertEqual(command[command.index("--runtime-sha256") + 1], runtime_digest)
                        self.assertEqual(command[command.index("--runtime-version") + 1], runtime_version)
                    result = Path(command[command.index("--output-dir") + 1])
                    result.mkdir(parents=True)
                    upgraded.append(result.parent.name)
                    checks = [{"passed": True, "binary_sha256": digest, "real_model": True, "engine": "cpu",
                        "upgrade_contract": "legacy-shim-v1",
                        "supervised_worker_checked": True, "global_engine_preserved": True, "distinct_vault_keys": True,
                        "source_and_keys_unchanged": True, "compatible_index_reused": True,
                        "forced_restart_checked": True, "old_rpc_checked": True, "old_rpc_authenticated": False,
                        "resident_stress": None, "in_process_checked": False,
                        "sequence": [{"account": account, "model_rows": {
                            name: {"name": name, "status": "ok"} for name in ["embedder", "model index"]}}
                            for account in ["main", "alternate", "main"]]}]
                    if standalone:
                        checks[0].update(upgrade_contract="standalone-v1", source_rpc_checked=True,
                            legacy_client_rejected=True, legacy_handoff_actor="fixture",
                            live_owner_restart_rejected=True, safe_restart_checked=True,
                            old_rpc_checked=False, forced_restart_checked=False,
                            runtime_mode="standalone_runtime", standalone_runtime_evidence=True,
                            runtime_binary_sha256=runtime_digest, runtime_version=runtime_version,
                            runtime_identity_receipts=[{"pid": 1234, "instance_id": "fake-child-only"}])
                    if checks_transform is not None:
                        checks = checks_transform(checks)
                    (result / "real-account-return-verification.json").write_text(
                        json.dumps([] if empty_checks else checks), encoding="utf-8")
            argv = ["test-published-upgrades.py", "--binary", str(candidate), "--target", self.target,
                    "--model-dir", str(root / "model"), "--legacy-model-dir", str(root / "legacy"),
                    "--output-dir", str(root / "reports")]
            if profile is not None:
                argv += ["--profile", profile]
            if cache_draft:
                folder = root / "reports" / "v1.0.10"
                folder.mkdir(parents=True)
                (folder.parent / "draft-baseline.json").write_text(json.dumps(releases[-1]), encoding="utf-8")
                for (tag, name), value in files.items():
                    if tag == "v1.0.10":
                        (folder / name).write_bytes(value)
                if corrupt_draft:
                    (folder / f"rsrs-{self.target}").write_bytes(b"corrupt cached seed")
                argv += ["--draft-baseline-cache", str(folder.parent)]
            if download_only:
                argv = [argv[0], "--download-only", "--target", self.target,
                        "--output-dir", str(root / "reports")]
            env = {key: value for key, value in os.environ.items()
                   if key not in ("RSRS_RUNTIME_BIN", "RSRS_ARTIFACT_SOURCE")
                   and not key.startswith("RSRS_PUBLISHED_")}
            if standalone and standalone_mode == "build":
                argv += ["--runtime-binary", str(runtime), "--runtime-sha256", runtime_digest,
                         "--runtime-version", runtime_version]
                env["RSRS_ARTIFACT_SOURCE"] = "build"
            elif standalone:
                env.update(RSRS_ARTIFACT_SOURCE="published-assets", GITHUB_ACTIONS="true",
                    RUNNER_ENVIRONMENT="github-hosted", RSRS_RUNTIME_BIN=str(runtime),
                    RSRS_PUBLISHED_RUNTIME_SHA256=runtime_digest, RSRS_PUBLISHED_RUNTIME_VERSION=runtime_version,
                    RSRS_PUBLISHED_ASSETS_SHA256="a" * 64, RSRS_PUBLISHED_BUNDLE_SHA256="b" * 64)
            with patch.object(sys, "argv", argv), patch("shutil.which", side_effect=lambda name: name), \
                    patch("subprocess.check_output", side_effect=output), patch("subprocess.run", side_effect=run), \
                    patch.dict(os.environ, env, clear=True):
                if missing_latest or registry is not None or empty_checks or checks_transform is not None or corrupt_draft:
                    with self.assertRaises((ValueError, AssertionError)):
                        runpy.run_path(str(Path(__file__).with_name("test-published-upgrades.py")), run_name="__main__")
                else:
                    if download_only:
                        with self.assertRaises(SystemExit) as exited:
                            runpy.run_path(str(Path(__file__).with_name("test-published-upgrades.py")), run_name="__main__")
                        self.assertEqual(exited.exception.code, 0)
                        self.assertEqual(json.loads((root / "reports/draft-baseline.json").read_text()), releases[-1])
                    else:
                        runpy.run_path(str(Path(__file__).with_name("test-published-upgrades.py")), run_name="__main__")
            report = root / "reports/published-upgrades.json"
            return upgraded, json.loads(report.read_text()) if report.exists() else None

    def test_critical_runs_latest_only_and_marks_partial_coverage(self):
        upgraded, report = self.run_fixture("critical")
        self.assertEqual(upgraded, ["v1.0.18"])
        self.assertEqual(report["selected_sources"], ["v1.0.18"])
        self.assertEqual(report["profile"], "critical")
        self.assertTrue(report["passed"])
        self.assertEqual(report["upgrade_contract"], "legacy-shim-v1")
        self.assertFalse(report["full_coverage"])
        self.assertFalse(report["all_published_sources_covered"])
        self.assertEqual(report["additional_draft_baselines"], [])

    def test_default_full_keeps_all_stables_and_both_baselines(self):
        upgraded, report = self.run_fixture()
        self.assertEqual(set(upgraded), {"v1.0.12", "v1.0.18", "v1.0.10", "v1.0.6-dev.37075716045"})
        self.assertEqual(report["profile"], "full")
        self.assertTrue(report["full_coverage"])
        self.assertTrue(report["all_published_sources_covered"])
        cached_upgrades, cached_report = self.run_fixture(cache_draft=True)
        self.assertEqual(set(cached_upgrades), set(upgraded))
        self.assertTrue(cached_report["all_published_sources_covered"])
        failed_upgrades, failed_report = self.run_fixture(cache_draft=True, corrupt_draft=True)
        self.assertNotIn("v1.0.10", failed_upgrades)
        self.assertFalse(failed_report["passed"])
        downloaded_upgrades, _ = self.run_fixture(download_only=True)
        self.assertEqual(downloaded_upgrades, [])

    def test_critical_missing_latest_fails_without_running_older(self):
        upgraded, report = self.run_fixture("critical", missing_latest=True)
        self.assertEqual(upgraded, [])
        self.assertFalse(report["passed"])
        self.assertFalse(report["full_coverage"])

    def test_missing_registry_stable_still_fails_in_both_profiles(self):
        for profile in ["critical", "full"]:
            upgraded, _ = self.run_fixture(profile, registry=["1.0.19"])
            self.assertEqual(upgraded, [])

    def test_empty_upgrade_checks_cannot_pass_either_profile(self):
        for profile in ["critical", "full"]:
            _, report = self.run_fixture(profile, empty_checks=True)
            self.assertFalse(report["passed"])
            self.assertFalse(report["full_coverage"])
            self.assertFalse(report["all_published_sources_covered"])

    def assert_rejected_checks(self, transform, standalone=False):
        for mode in (["build", "published-assets"] if standalone else ["published-assets"]):
            for profile in ["critical", "full"]:
                _, report = self.run_fixture(profile, checks_transform=transform,
                    standalone=standalone, standalone_mode=mode)
                self.assertFalse(report["passed"])
                self.assertFalse(report["full_coverage"])
                self.assertFalse(report["all_published_sources_covered"])

    def test_sparse_or_duplicate_candidate_reports_fail(self):
        self.assert_rejected_checks(lambda checks: [{"passed": True, "binary_sha256": checks[0]["binary_sha256"]}])
        self.assert_rejected_checks(lambda checks: checks * 2)

    def test_each_required_upgrade_flag_must_be_present_and_strictly_true(self):
        flags = ["passed", "real_model", "supervised_worker_checked", "global_engine_preserved",
                 "distinct_vault_keys", "source_and_keys_unchanged", "compatible_index_reused",
                 "forced_restart_checked", "old_rpc_checked"]
        for name in flags:
            with self.subTest(name=name, value="missing"):
                self.assert_rejected_checks(lambda checks: [{key: value for key, value in checks[0].items() if key != name}])
            for value in [False, 1, "true"]:
                with self.subTest(name=name, value=value):
                    self.assert_rejected_checks(lambda checks: [{**checks[0], name: value}])

    def test_candidate_hash_and_cpu_engine_must_match(self):
        for standalone in [False, True]:
            for name, value in [("binary_sha256", "wrong"), ("engine", "gpu")]:
                with self.subTest(name=name, standalone=standalone):
                    self.assert_rejected_checks(lambda checks: [{**checks[0], name: value}], standalone)

    def test_account_sequence_cannot_be_missing_shortened_or_reordered(self):
        for standalone in [False, True]:
            for sequence in [None, [], ["main", "alternate"], ["main", "main", "alternate"]]:
                with self.subTest(sequence=sequence, standalone=standalone):
                    self.assert_rejected_checks(lambda checks: [{**checks[0], "sequence": None if sequence is None else [
                        {**checks[0]["sequence"][0], "account": account} for account in sequence]}], standalone)

    def test_each_account_requires_both_successful_model_rows(self):
        for standalone in [False, True]:
            for index in range(3):
                for rows in [None, {}, {"embedder": {"status": "ok"}},
                             {"embedder": {"status": "ok"}, "model index": {"status": "fail"}},
                             {"embedder": {}, "model index": {"status": "ok"}}]:
                    with self.subTest(index=index, rows=rows, standalone=standalone):
                        self.assert_rejected_checks(lambda checks: [{**checks[0], "sequence": [
                            {**step, "model_rows": rows} if position == index else step
                            for position, step in enumerate(checks[0]["sequence"])]}], standalone)

    def test_standalone_contract_passes_both_profiles_without_legacy_success_claims(self):
        for mode in ["build", "published-assets"]:
            for profile in ["critical", "full"]:
                with self.subTest(mode=mode, profile=profile):
                    _, report = self.run_fixture(profile, standalone=True, standalone_mode=mode)
                    self.assertTrue(report["passed"])
                    self.assertEqual(report["upgrade_contract"], "standalone-v1")
                    self.assertTrue(all(item["upgrade_contract"] == "standalone-v1" for item in report["sources"]))

    def test_contract_is_required_known_and_matches_selected_mode(self):
        for standalone in [False, True]:
            self.assert_rejected_checks(lambda checks: [{key: value for key, value in checks[0].items()
                                                        if key != "upgrade_contract"}], standalone)
            for contract in [None, "", True, 1, "unknown-v1",
                             "legacy-shim-v1" if standalone else "standalone-v1"]:
                with self.subTest(standalone=standalone, contract=contract):
                    self.assert_rejected_checks(lambda checks: [{**checks[0], "upgrade_contract": contract}], standalone)

    def test_standalone_required_flags_are_present_and_strictly_true(self):
        flags = ["passed", "real_model", "supervised_worker_checked", "global_engine_preserved",
                 "distinct_vault_keys", "source_and_keys_unchanged", "compatible_index_reused",
                 "source_rpc_checked", "legacy_client_rejected", "live_owner_restart_rejected",
                 "safe_restart_checked", "standalone_runtime_evidence"]
        self.assert_rejected_checks(lambda checks: [{key: value for key, value in checks[0].items()
                                                    if key not in flags}], True)
        for name in flags:
            with self.subTest(name=name, value="missing"):
                self.assert_rejected_checks(lambda checks: [{key: value for key, value in checks[0].items()
                                                            if key != name}], True)
            for value in [None, False, 0, 1, "true"]:
                with self.subTest(name=name, value=value):
                    self.assert_rejected_checks(lambda checks: [{**checks[0], name: value}], True)

    def test_standalone_legacy_flags_must_be_explicit_false(self):
        for name in ["old_rpc_checked", "forced_restart_checked"]:
            self.assert_rejected_checks(lambda checks: [{key: value for key, value in checks[0].items()
                                                        if key != name}], True)
            for value in [None, True, 0, 1, "false"]:
                with self.subTest(name=name, value=value):
                    self.assert_rejected_checks(lambda checks: [{**checks[0], name: value}], True)

    def test_standalone_requires_fixture_handoff_and_runtime_evidence(self):
        fields = {"legacy_handoff_actor": [None, "", True, "runtime", "client"],
                  "runtime_mode": [None, "explicit_cli_shim"],
                  "runtime_binary_sha256": [None, "wrong"], "runtime_version": [None, "wrong"],
                  "runtime_identity_receipts": [None, [], [None]]}
        for name, values in fields.items():
            self.assert_rejected_checks(lambda checks: [{key: value for key, value in checks[0].items()
                                                        if key != name}], True)
            for value in values:
                with self.subTest(name=name, value=value):
                    self.assert_rejected_checks(lambda checks: [{**checks[0], name: value}], True)


if __name__ == "__main__":
    unittest.main()
