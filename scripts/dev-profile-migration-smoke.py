#!/usr/bin/env python3
"""Hosted CI only: real encrypted profiles, keyring aliases, WAL and restart migration."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import sqlite3
import subprocess
import sys
import time

spec = importlib.util.spec_from_file_location("vault_smoke_support", Path(__file__).with_name("dev-legacy-vault-smoke.py"))
support = importlib.util.module_from_spec(spec)
spec.loader.exec_module(support)
keyring_spec = importlib.util.spec_from_file_location("migration_native_keyring", Path(__file__).with_name("dev-migration-keyring.py"))
keyring_backend = importlib.util.module_from_spec(keyring_spec)
keyring_spec.loader.exec_module(keyring_backend)
require, digest = support.require, support.digest
REQUIRED = ("model_cpu_real", "onememory_multiaccount_wal_migrated",
    "respire_compatibility_migrated", "legacy_keys_migrated_without_super_override",
    "legacy_api_defaults_rewritten", "migration_repeated_start_idempotent",
    "migration_interrupted_restart_recovered", "existing_rsrs_preserved_and_legacy_imported",
    "migrated_outbox_sync_and_independent_decrypt", "migration_incompatible_primary_keys_rejected",
    "migration_symlink_root_rejected", "migration_client_only_does_not_write")


class Smoke(support.Smoke):
    def __init__(self, args):
        super().__init__(args)
        self.keys = None
        self.wal_connections = []
        self.report.update(required_cases=list(REQUIRED), cases={}, passed=False,
            scope="Synthetic home/profile data and exact random-user native keyring entries only.",
            platform=sys.platform, keyring_cleanup={"passed": False, "remaining_entries": []})

    def env(self, name, user=None):
        env = super().env(name, user)
        if self.keys is not None:
            self.keys.configure_env(env)
        return env

    def reserve_account(self, user):
        for slot in ("super:", "pass:"):
            self.keys.reserve("rsrs", slot + user)

    def reserve_alias(self, source):
        alias = "legacy-" + keyring_backend.canonical_identity(source)[:16]
        for slot in ("super:", "pass:"):
            self.keys.reserve("rsrs", slot + alias)
        return alias

    def save(self):
        (self.root / "migration-coverage.json").write_text(json.dumps(self.report, indent=2) + "\n", encoding="utf-8")

    def default_env(self, env):
        result = dict(env)
        result.pop("ONEMEMORY_DATA_DIR", None)
        result.pop("ONEMEMORY_SUPER", None)
        return result

    def seed(self, env, path, service, label):
        path.mkdir(parents=True, exist_ok=True)
        env = dict(env, ONEMEMORY_DATA_DIR=str(path))
        user, password = "ci-migrate-" + secrets.token_hex(8), secrets.token_urlsafe(32)
        self.reserve_account(user)
        account = {"user": user, "token": None, "confirmed": False}
        self.accounts.append(account)
        self.report["cloud_cleanup"]["remaining_users"].append(user)
        self.save()
        value = self.cli(env, "register", "--addr", support.UPSTREAM, "--user", user, "--pass", password)
        session = self.session(env)
        require(value["summary"].get("ok") is True and value["summary"].get("user") == user
            and session.get("user") == user and session.get("addr") == support.UPSTREAM
            and bool(session.get("token")), "migration_registered_identity_mismatch")
        account.update(token=session["token"], confirmed=True)
        code = value["summary"].get("super")
        require(isinstance(code, str) and bool(code), "migration_super_missing")
        require(self.keys.read("rsrs", "super:" + user) == code
            and self.keys.read("rsrs", "pass:" + user) == password,
            "registered_native_credentials_not_in_owned_store")
        env["ONEMEMORY_SUPER"] = code
        self.cli(env, "config", "--addr", support.UPSTREAM, "--autosync", "false")
        text = "Synthetic unsynchronized migration content " + label
        created = self.cli(env, "remember", text, "--title", label, "--force", "--importance", "important")
        memory_id = created["summary"]["id"]
        db = path / "onememory.db"
        connection = sqlite3.connect(db)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA wal_autocheckpoint=0")
        connection.execute("CREATE TABLE IF NOT EXISTS migration_wal_fixture(marker TEXT PRIMARY KEY)")
        connection.execute("INSERT INTO migration_wal_fixture VALUES(?)", (label,))
        connection.commit()
        require((path / "onememory.db-wal").stat().st_size > 0, "migration_wal_fixture_empty")
        row = connection.execute("SELECT ciphertext,nonce FROM memories WHERE id=?", (memory_id,)).fetchone()
        require(row and connection.execute("SELECT COUNT(*) FROM sync_outbox WHERE state='pending'").fetchone()[0] > 0,
            "migration_outbox_fixture_not_pending")
        self.wal_connections.append(connection)
        self.keys.put(service, "super:" + user, code)
        self.keys.put(service, "pass:" + user, password)
        # The old service is the only credential source, not an environment override.
        self.keys.remove("rsrs", "super:" + user)
        self.keys.remove("rsrs", "pass:" + user)
        env.pop("ONEMEMORY_SUPER", None)
        session["addr"] = {"1memory": "https://api.1memory.ai", "memocap": "https://api.memocap.ai"}.get(service,
            "https://api.respire.ai")
        self.write_session(env, session)
        config_path = path / "client.json"
        config = json.loads(config_path.read_text())
        config["addr"] = session["addr"]
        config_path.write_text(json.dumps(config), encoding="utf-8")
        alias = self.reserve_alias(path)
        return {"account": account, "password": password, "code": code, "service": service,
            "source": path, "id": memory_id, "text": text, "label": label, "cipher": row, "alias": alias}

    def migrated(self, home, fixtures):
        root = home / ".rsrs"
        require(root.is_dir(), "migration_target_missing")
        sessions = {}
        for path in root.rglob("session.json"):
            value = json.loads(path.read_text())
            if value.get("user") in {f["account"]["user"] for f in fixtures}:
                require(value["user"] not in sessions, "migration_profile_duplicate")
                sessions[value["user"]] = (path, value)
        require(len(sessions) == len(fixtures), "migration_profiles_missing")
        for fixture in fixtures:
            user = fixture["account"]["user"]
            session_path, value = sessions[user]
            profile = session_path.parent
            require(value.get("addr") == "https://api.rsrs.rs", "legacy_api_default_not_rewritten")
            require((profile / ".rsrs-migration.json").is_file(), "migration_receipt_missing")
            alias = value.get("keyring_account")
            require(isinstance(alias, str) and alias.startswith("legacy-"), "migration_key_alias_missing")
            require(alias == fixture["alias"], "migration_native_alias_identity_mismatch")
            require(self.keys.read("rsrs", "super:" + alias) == fixture["code"], "migration_key_changed")
            require(self.keys.read("rsrs", "pass:" + alias) == fixture["password"], "migration_login_password_changed")
            require(self.keys.read(fixture["service"], "super:" + user) == fixture["code"], "legacy_key_source_changed")
            require(self.keys.read(fixture["service"], "pass:" + user) == fixture["password"], "legacy_password_source_changed")
            with sqlite3.connect((fixture["source"] / "onememory.db").as_uri() + "?mode=ro", uri=True) as source_db:
                require(source_db.execute("SELECT ciphertext,nonce FROM memories WHERE id=?", (fixture["id"],)).fetchone() == fixture["cipher"],
                    "legacy_source_ciphertext_changed")
            with sqlite3.connect((profile / "onememory.db").as_uri() + "?mode=ro", uri=True) as db:
                require(db.execute("PRAGMA integrity_check").fetchone()[0] == "ok", "migrated_database_invalid")
                require(db.execute("SELECT ciphertext,nonce FROM memories WHERE id=?", (fixture["id"],)).fetchone() == fixture["cipher"],
                    "migration_changed_ciphertext")
                require(db.execute("SELECT marker FROM migration_wal_fixture").fetchone()[0] == fixture["label"], "migration_lost_committed_wal")
                require(db.execute("SELECT COUNT(*) FROM sync_outbox WHERE state='pending'").fetchone()[0] > 0, "migration_lost_outbox")
            fixture["destination"] = profile
        return sessions

    def case(self, name, sources, target=False, interrupt=False):
        env = self.env(name)
        home = Path(env["HOME"])
        fixtures = []
        for folder, service in sources:
            fixture = self.seed(env, home / folder, service, name + "-" + folder)
            fixtures.append(fixture)
        if name == "multiaccount":
            other = self.seed(env, home / ".onememory/accounts/second", "1memory", "multiaccount-secondary")
            fixtures.append(other)
            config_path = home / ".onememory/client.json"
            config = json.loads(config_path.read_text())
            config["data_dir"] = str(other["source"])
            config_path.write_text(json.dumps(config), encoding="utf-8")
            old_lock = sqlite3.connect(fixtures[0]["source"] / "lock.db")
            old_lock.execute("CREATE TABLE IF NOT EXISTS migration_lock_fixture(value TEXT)")
            old_lock.commit()
            old_lock.execute("BEGIN EXCLUSIVE")
            self.wal_connections.append(old_lock)
        if target:
            current = self.seed(env, home / ".rsrs", "rsrs", name + "-existing-rsrs")
            # A current profile must keep its existing credentials and URL untouched.
            self.keys.put("rsrs", "super:" + current["account"]["user"], current["code"])
            self.keys.put("rsrs", "pass:" + current["account"]["user"], current["password"])
            current_env = dict(env, ONEMEMORY_DATA_DIR=str(current["source"]))
            session = self.session(current_env)
            session["addr"] = support.UPSTREAM
            self.write_session(current_env, session)
            self.cli(current_env, "config", "--addr", support.UPSTREAM, "--autosync", "false")
        default = self.default_env(env)
        if interrupt:
            padding = fixtures[0]["source"] / "migration-copy-fixture.bin"
            with padding.open("wb") as stream:
                for _ in range(64):
                    stream.write(bytes(1024 * 1024))
            process = subprocess.Popen([str(self.args.binary), "--direct", "--json", "status"],
                env=default, cwd=self.root, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            deadline = time.monotonic() + 30
            stage_seen = False
            while process.poll() is None and time.monotonic() < deadline:
                stage = home / ".rsrs-migration-staging"
                if stage.is_dir() and any(p.is_dir() for p in stage.iterdir()) and not (home / ".rsrs").exists():
                    stage_seen = True
                    process.kill()
                    break
                time.sleep(0.002)
            if process.poll() is None:
                process.kill()
            process.wait(timeout=10)
            require(stage_seen, "interruption_fixture_did_not_reach_real_stage")
            require(not (home / ".rsrs").exists(), "interruption_fixture_missed_prepublication_window")
        self.cli(default, "status")
        self.migrated(home, fixtures)
        for fixture in fixtures:
            user_env = dict(default, ONEMEMORY_DATA_DIR=str(fixture["destination"]))
            require("ONEMEMORY_SUPER" not in user_env, "migration_super_override_present")
            self.read_entry(user_env, fixture["id"], fixture["text"])
        if target:
            with sqlite3.connect(current["source"] / "onememory.db") as db:
                require(db.execute("SELECT ciphertext,nonce FROM memories WHERE id=?", (current["id"],)).fetchone() == current["cipher"],
                    "existing_target_data_overwritten")
            self.read_entry(current_env, current["id"], current["text"])
            self.passed("existing_rsrs_preserved_and_legacy_imported", imported=len(fixtures))
        before = {str(p.relative_to(home)): digest(p) for p in (home / ".rsrs").rglob(".rsrs-migration.json")}
        self.cli(default, "status")
        require(before == {str(p.relative_to(home)): digest(p) for p in (home / ".rsrs").rglob(".rsrs-migration.json")},
            "repeat_start_changed_receipts")
        require(len([p for p in (home / ".rsrs").rglob("session.json") if json.loads(p.read_text()).get("user") in
            {f["account"]["user"] for f in fixtures}]) == len(fixtures), "repeat_start_duplicated_profiles")
        if name == "multiaccount":
            receipt = json.loads((fixtures[0]["destination"] / ".rsrs-migration.json").read_text())
            require(receipt.get("snapshot_only") is True and receipt.get("legacy_runtime_active") is True,
                "active_legacy_lock_snapshot_not_declared")
            selected = self.cli(default, "config")["summary"]["data_dir"]
            require(Path(selected).resolve() == fixtures[-1]["destination"].resolve(), "migration_active_account_not_preserved")
            self.passed("onememory_multiaccount_wal_migrated", profiles=len(fixtures))
            self.passed("legacy_keys_migrated_without_super_override", old_service_unchanged=True)
            self.passed("legacy_api_defaults_rewritten", verified="old defaults to api.rsrs.rs; dev redirect only after verification")
            self.passed("migration_repeated_start_idempotent", profiles=len(fixtures))
            for fixture in fixtures:
                profile_env = dict(default, ONEMEMORY_DATA_DIR=str(fixture["destination"]))
                session = self.session(profile_env)
                session["addr"] = support.UPSTREAM
                self.write_session(profile_env, session)
                self.cli(profile_env, "config", "--addr", support.UPSTREAM, "--autosync", "false")
                self.cli(profile_env, "remember", "New-directory migration write", "--title", "post-migration", "--force")
                self.cli(profile_env, "sync")
                user = fixture["account"]["user"]
                remote = self.env("independent-" + user, user)
                remote["ONEMEMORY_SUPER"] = fixture["code"]
                self.cli(remote, "login", "--addr", support.UPSTREAM, "--user", user, "--pass", fixture["password"], "--super", fixture["code"])
                fixture["account"]["token"] = self.session(remote)["token"]
                self.cli(remote, "sync")
                self.read_entry(remote, fixture["id"], fixture["text"])
                rows = self.cli(remote, "list", "--limit", "100")
                require("post-migration" in json.dumps(rows), "new_directory_write_not_synced")
            self.passed("migrated_outbox_sync_and_independent_decrypt", profiles=len(fixtures))
        elif interrupt:
            self.passed("migration_interrupted_restart_recovered", real_stage_observed=True)
        elif not target:
            self.passed("respire_compatibility_migrated", profiles=len(fixtures))

    def run(self):
        expected_server = os.environ.get("RESPIRE_DEV_SERVER_SHA", "")
        require(os.environ.get("RESPIRE_DEV_SERVER_ADDR") == support.UPSTREAM
            and re.fullmatch("[0-9a-f]{40}", expected_server), "exact_development_server_required")
        with self.opener.open(support.UPSTREAM + "/ready", timeout=45) as ready:
            require(ready.status == 200 and ready.headers.get("X-Respire-Server-SHA") == expected_server,
                "development_server_revision_mismatch")
        self.report["server_sha"] = expected_server
        self.keys = keyring_backend.create(self.root / "keyring-home")
        self.report["keyring_backend"] = self.keys.name
        env = self.env("model-probe")
        version = subprocess.run([str(self.args.binary), "--version"], env=env, capture_output=True, timeout=20)
        require(version.returncode == 0 and re.search(r"(?<!\S)" + re.escape(self.args.version) + r"(?!\S)", version.stdout.decode()), "binary_version_mismatch")
        self.cli(env, "model", "install-bge", timeout=900)
        require(all(digest(self.model / p) == h for p, h in support.MODEL_HASHES.items()), "model_hash_mismatch")
        self.cli(env, "model", "engine", "cpu")
        probe = self.cli(env, "model", "probe", "--model", "legacy")["summary"]
        require(probe.get("ready") is True and probe.get("dimensions") == 768 and str(probe.get("selected")).lower() == "cpu", "real_cpu_probe_failed")
        self.passed("model_cpu_real", dimensions=768)
        self.case("multiaccount", [(".onememory", "1memory")])
        self.case("respire", [(".respire", "respire")])
        self.case("interrupted", [(".respire", "respire")], interrupt=True)
        self.case("collision", [(".onememory", "1memory"), (".respire", "memocap")], target=True)
        self.negative_cases()
        self.report["status"] = "passed"

    def negative_cases(self):
        env = self.env("negative-source")
        fixture = self.seed(env, Path(env["HOME"]) / ".onememory", "1memory", "negative-source")
        for label, primary in (("missing-pk", ""), ("composite-pk", ",PRIMARY KEY(id,title)")):
            attempt = self.env(label)
            source = Path(attempt["HOME"]) / ".onememory"
            source.mkdir()
            self.reserve_alias(source)
            shutil.copyfile(fixture["source"] / "session.json", source / "session.json")
            with sqlite3.connect(source / "onememory.db") as db:
                db.execute("CREATE TABLE memories(id TEXT,user TEXT,title TEXT,ciphertext TEXT,nonce TEXT,created_at TEXT,updated_at TEXT" + primary + ")")
                db.execute("INSERT INTO memories VALUES(?,?,?,?,?,?,?)", (fixture["id"],fixture["account"]["user"],label,
                    fixture["cipher"][0],fixture["cipher"][1],"2026-10-03T00:00:00Z","2026-10-03T00:00:00Z"))
            before = digest(source / "onememory.db")
            result = subprocess.run([str(self.args.binary), "--direct", "--json", "status"],
                env=self.default_env(attempt), cwd=self.root, capture_output=True, timeout=60)
            require(result.returncode != 0 and not (Path(attempt["HOME"]) / ".rsrs").exists(), "invalid_primary_key_migration_not_rejected")
            require(digest(source / "onememory.db") == before, "rejected_source_database_changed")
        self.passed("migration_incompatible_primary_keys_rejected", genuine_ciphertext_preserved=True, variants=2)
        link_env = self.env("symlink-root")
        link_home = Path(link_env["HOME"])
        (link_home / ".onememory").symlink_to(fixture["source"], target_is_directory=True)
        result = subprocess.run([str(self.args.binary), "--direct", "--json", "status"],
            env=self.default_env(link_env), cwd=self.root, capture_output=True, timeout=60)
        require(result.returncode != 0 and not (link_home / ".rsrs").exists(), "symlink_root_migration_not_rejected")
        self.passed("migration_symlink_root_rejected", external_target_is_owned_fixture=True)
        source_session = digest(fixture["source"] / "session.json")
        for variable in ("ONEMEMORY_CLIENT_ONLY", "ONEMEMORY_NO_AUTOSTART"):
            guarded = self.default_env(env)
            guarded[variable] = "1"
            result = subprocess.run([str(self.args.binary), "--version"], env=guarded,
                cwd=self.root, capture_output=True, timeout=30)
            require(result.returncode == 0 and not (Path(env["HOME"]) / ".rsrs").exists()
                and digest(fixture["source"] / "session.json") == source_session, "client_only_migration_wrote_data")
        self.passed("migration_client_only_does_not_write", guards=2)


def main():
    require(os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and sys.platform in ("linux", "darwin", "win32"), "disposable_native_hosted_runner_required")
    parser = argparse.ArgumentParser()
    for name in ("binary", "root"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("binary-sha256", "source-sha", "version"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    require(re.fullmatch(r"[0-9a-f]{64}", args.binary_sha256) and args.binary.is_absolute()
        and args.binary.is_file() and digest(args.binary) == args.binary_sha256, "binary_hash_mismatch")
    require(re.fullmatch(r"[0-9a-f]{40}", args.source_sha) and args.source_sha == os.environ.get("CLI_SHA"), "verified_artifact_source_sha_mismatch")
    require(args.version and not any(c.isspace() for c in args.version), "version_invalid")
    temp = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    require(args.root.is_absolute() and not args.root.exists(), "root_not_fresh")
    args.root = args.root.resolve()
    require(args.root != temp and args.root.is_relative_to(temp), "root_outside_runner_temp")
    smoke = Smoke(args)
    try:
        smoke.run()
    except Exception as error:
        smoke.report.update(status="failed", failure=str(error) if isinstance(error, RuntimeError) else type(error).__name__)
    finally:
        for connection in smoke.wal_connections:
            connection.close()
        smoke.cleanup()
        if smoke.keys is not None:
            try:
                smoke.report["keyring_cleanup"] = smoke.keys.cleanup()
            except Exception as error:
                smoke.report["keyring_cleanup"] = {"passed": False, "failure_code": type(error).__name__,
                    "remaining_entries": ["cleanup_not_verified"]}
        smoke.report["missing_cases"] = [case for case in REQUIRED if case not in smoke.report["cases"]]
        smoke.report["passed"] = smoke.report["status"] == "passed" and not smoke.report["missing_cases"] \
            and smoke.report["cloud_cleanup"]["passed"] and smoke.report["keyring_cleanup"]["passed"]
        smoke.save()
    print(json.dumps({"passed": smoke.report["passed"], "cases": len(smoke.report["cases"]),
        "report": str(smoke.root / "migration-coverage.json")}))
    return 0 if smoke.report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
