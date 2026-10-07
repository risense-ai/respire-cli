#!/usr/bin/env python3
"""Real Linux CLI SIGINT recovery; only synthetic accounts and loopback HTTP."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import re
import socket
import sqlite3
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

spec = importlib.util.spec_from_file_location("legacy", Path(__file__).with_name("dev-legacy-vault-smoke.py"))
legacy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(legacy)
require = legacy.require


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("binary", "root", "model-dir"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("binary-sha256", "source-sha", "version"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--native-credentials", action="store_true")
    args = parser.parse_args()
    require(os.name == "posix", "SIGINT_fixture_requires_posix")
    require(legacy.digest(args.binary) == args.binary_sha256, "binary_hash_mismatch")
    require(not args.root.exists(), "fresh_fixture_required")
    args.root.mkdir(mode=0o700)
    report = {"source_sha": args.source_sha, "version": args.version,
              "binary_sha256": args.binary_sha256, "passed": False, "cases": {}}
    code = "A3-" + "-".join(secrets.token_hex(3).upper() for _ in range(6))
    urk = secrets.token_bytes(32)
    salt, nonce = secrets.token_hex(16), secrets.token_bytes(12)
    v4 = {"version": 4, "kdf_salt": salt, "urk_nonce": nonce.hex(),
          "wrapped_urk": legacy.PREFIX + AESGCM(legacy.v4_kek(code, salt, legacy.PREFIX)).encrypt(nonce, urk, None).hex()}
    salt, nonce = secrets.token_hex(16), secrets.token_bytes(12)
    old_super = "synthetic-legacy-super"
    v2 = {"version": 2, "kdf_salt": salt, "urk_nonce": nonce.hex(),
          "wrapped_urk": AESGCM(legacy.legacy_kek(2, old_super, "", salt)).encrypt(nonce, urk, None).hex()}
    migrated_v2 = dict(v2, wrapped_urk=legacy.PREFIX + v2["wrapped_urk"])
    old_auth_salt = legacy.hkdf(b"synthetic", None, b"onememory:auth-salt:v1", length=16).hex()
    state = {"vault": v4, "auth_salt": old_auth_salt, "gets": 0, "posts": 0, "barrier": None}
    reached, release = threading.Event(), threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def reply(self, value):
            body = json.dumps(value).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass  # Expected: the test terminates its own waiting CLI.

        def do_POST(self):
            data = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
            if self.path == "/login":
                self.reply({"user": "synthetic", "token": "synthetic-token", "session_id": "fixture"})
            elif self.path == "/api/self/vault":
                state["vault"] = data
                state["posts"] += 1
                if state["barrier"] == "after_publish":
                    reached.set()
                    release.wait(120)
                self.reply({"ok": True})
            elif self.path == "/api/self/password":
                require(self.headers.get("Authorization") == "Bearer synthetic-token", "password_update_not_authorized")
                salt_bytes = bytes.fromhex(data["salt"].removeprefix(legacy.PREFIX))
                require(data["pass_hash"] == hashlib.pbkdf2_hmac("sha256", b"synthetic-password", salt_bytes, 100000, 32).hex(),
                    "original_login_password_changed")
                state["auth_salt"] = data["salt"]
                self.reply({"updated": True})
            else:
                self.send_error(404)

        def do_GET(self):
            if self.path == "/auth/salt?user=synthetic":
                self.reply({"salt": state["auth_salt"]})
                return
            if self.path != "/api/self/vault":
                self.send_error(404)
                return
            state["gets"] += 1
            if state["barrier"] == "before_publish" and state["gets"] == 2:
                reached.set()
                release.wait(120)
            self.reply(state["vault"])

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    addr = f"http://127.0.0.1:{server.server_port}"
    root = args.root / "library"
    root.mkdir(mode=0o700)
    env = {k: v for k, v in os.environ.items() if not k.startswith(("RSRS_", "ONEMEMORY_", "RESPIRE_", "XDG_"))}
    home = args.root / "home"
    home.mkdir(mode=0o700)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    env.update(HOME=str(home), RSRS_DATA_DIR=str(root), RSRS_SUPER=code,
               RSRS_RPC_PORT=str(port), RSRS_M3_DIR=str(args.model_dir),
               RSRS_NO_AUTOSYNC="1", RSRS_UPDATE_CHECK="0", RSRS_ENGINE="cpu")
    keys = None
    if args.native_credentials:
        native_root = args.root / "native-store"
        native_root.mkdir(mode=0o700)
        key_spec = importlib.util.spec_from_file_location("private_credentials", Path(__file__).with_name("dev-migration-secret-service.py"))
        key_module = importlib.util.module_from_spec(key_spec)
        key_spec.loader.exec_module(key_module)
        keys = key_module.SecretServiceKeys(native_root)
        keys.configure_env(env)
    session = root / "session.json"
    config = root / "client.json"
    config_bytes = json.dumps({"data_dir": str(root), "api_base": "https://previous.invalid", "custom": "preserve"}).encode()
    config.write_bytes(config_bytes)

    def write_session(vault):
        value = {"user": "synthetic", "addr": addr, "token": "synthetic-token", "vault_version": vault["version"],
                 **{k: v for k, v in vault.items() if k != "version"}}
        if vault["wrapped_urk"].startswith(legacy.PREFIX):
            value["crypto_namespace"] = legacy.PREFIX
        session.write_text(json.dumps(value))
        session.chmod(0o600)
        return session.read_bytes()

    def cli(*flags, success=True):
        command_env = dict(env)
        if keys and "migrate" in flags:
            command_env.pop("RSRS_SUPER")
        elif "migrate" in flags:
            command_env["RSRS_SUPER"] = old_super
        result = subprocess.run([str(args.binary), *flags], env=command_env, capture_output=True, timeout=180)
        if (result.returncode == 0) != success:
            try:
                errors = json.loads(result.stdout).get("errors", [])
                diagnostic = "; ".join(str(error) for error in errors)
            except (ValueError, UnicodeError, AttributeError):
                diagnostic = "CLI returned no structured error"
            diagnostic = diagnostic or result.stderr.decode(errors="replace")[-1500:]
            for secret in (code, old_super, "synthetic-password", "synthetic-token"):
                diagnostic = diagnostic.replace(secret, "[redacted]")
            report["failure"] = {"exit_code": result.returncode, "error": diagnostic[:1500]}
            raise RuntimeError("CLI_failed:" + diagnostic[:1500])
        return result

    migration = ["--direct", "--json", "migrate", "--vault", "--addr", addr, "--user", "synthetic",
                 "--pass=synthetic-password", "--super", old_super, "--new-super", old_super]
    child = None
    migration_keys = None
    try:
        version = cli("--version").stdout.decode()
        require(args.version in version, "binary_version_mismatch")
        write_session(v4)
        cli("--direct", "--json", "remember", "Synthetic interruption ciphertext", "--title", "Interruption fixture", "--force", "--importance", "important")
        database = root / "rsrs.db"

        def ciphertexts():
            with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as db:
                return db.execute("SELECT id,ciphertext,nonce FROM memories ORDER BY id").fetchall()

        original_rows = ciphertexts()
        require(len(original_rows) == 1, "ciphertext_fixture_missing")
        for barrier in ("before_publish", "after_publish"):
            state.update(vault=dict(v2), gets=0, posts=0, barrier=barrier)
            # Transaction barriers start after full library conversion, which is
            # exercised independently by the real profile migration fixture.
            legacy_bytes = write_session(migrated_v2)
            config.write_bytes(config_bytes)
            reached.clear()
            release.clear()
            command_env = dict(env)
            if keys:
                command_env.pop("RSRS_SUPER")
            else:
                command_env["RSRS_SUPER"] = old_super
            child = subprocess.Popen([str(args.binary), *migration], env=command_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            require(reached.wait(120), "commit_barrier_not_reached")
            require(json.loads(session.read_bytes())["wrapped_urk"].startswith(legacy.PREFIX)
                and json.loads(session.read_bytes())["vault_version"] == 2, "original_vault_factors_changed")
            require((root / ".login-recovery.json").is_file(), "durable_recovery_missing")
            alias = json.loads(session.read_bytes()).get("keyring_account")
            if keys:
                require(re.fullmatch(r"login-[a-f0-9]{32}", alias or "") is not None, "native_alias_missing")
                require(json.loads(session.read_bytes()).get("keyring_backend") == "secret_service", "native_backend_not_used")
                attributes = {"service": "rsrs", "username": "super:" + alias}
                items = list(keys.collection.search_items(attributes))
                require(len(items) == 1 and items[0].get_secret().decode() == old_super, "native_credential_not_written")
                password_attributes = {"service": "rsrs", "username": "pass:" + alias}
                passwords = list(keys.collection.search_items(password_attributes))
                require(len(passwords) == 1 and passwords[0].get_secret().decode() == "synthetic-password", "original_password_not_written")
            child.send_signal(signal.SIGINT)
            child.communicate(timeout=15)
            require(child.returncode == -signal.SIGINT, "owned_child_not_interrupted")
            child = None
            release.set()
            state["barrier"] = None
            require(state["posts"] == (0 if barrier == "before_publish" else 1), "publication_window_not_proven")
            # A rejected normal login first runs durable recovery. No manual edit.
            cli("login", "--interactive", "--addr", addr, "--user", "synthetic", "--pass=synthetic-password", "--super=wrong", success=False)
            require(session.read_bytes() == legacy_bytes and config.read_bytes() == config_bytes, "original_profile_not_restored")
            require(not (root / ".login-recovery.json").exists(), "recovery_not_retired")
            if keys:
                require(not list(keys.collection.search_items(attributes)), "interrupted_native_credential_not_deleted")
                require(not list(keys.collection.search_items(password_attributes)), "interrupted_native_password_not_deleted")
            cli(*migration)
            require(state["vault"]["version"] == 2 and state["posts"] == 1, "migration_retry_not_idempotent")
            vault = state["vault"]
            require(AESGCM(legacy.legacy_kek(2, old_super, "", vault["kdf_salt"], current=True)).decrypt(
                bytes.fromhex(vault["urk_nonce"]), legacy.encrypted_bytes(vault["wrapped_urk"]), None) == urk, "data_key_changed")
            require(ciphertexts() == original_rows, "original_ciphertexts_changed")
            require(json.loads(config.read_bytes()) == json.loads(config_bytes), "API_config_changed")
            cli("--runtime-internal", "--stop")
            report["cases"][barrier + "_SIGINT_retry"] = {"passed": True, "ciphertext_preserved": True, "original_profile_restored": True,
                                                          "credential_mode": "secret_service" if keys else "headless"}
        # DEV.4 has no journal. Preserve its inconsistent profile and recover by
        # importing the actual original library through the public migration API.
        state.update(vault=dict(v2), gets=0, posts=0, barrier=None)
        write_session(v4)
        before = session.read_bytes()
        wrong = list(migration)
        wrong[-1] = "A3-000000-000000-000000-000000-000000-000000"
        cli(*wrong, success=False)
        require(session.read_bytes() == before and state["posts"] == 0, "wrong_recovery_modified_state")
        cli(*migration, success=False)
        require(session.read_bytes() == before and state["posts"] == 0, "inconsistent_factors_modified_state")
        if keys is None:
            key_spec = importlib.util.spec_from_file_location("migration_keys", Path(__file__).with_name("dev-migration-keyring.py"))
            key_module = importlib.util.module_from_spec(key_spec)
            key_spec.loader.exec_module(key_module)
            migration_keys = key_module.create(args.root / "original-profile-keyring")
            migration_keys.configure_env(env)
            env["DBUS_SESSION_BUS_ADDRESS"] = "unix:path=" + str(args.root / "missing-secret-service.sock")
        else:
            migration_keys = keys
        source = home / ".onememory"
        source.mkdir(mode=0o700)
        source_database = source / "onememory.db"
        with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as original, sqlite3.connect(source_database) as backup:
            original.backup(backup)
            for memory_id, ciphertext, old_nonce in original_rows:
                plaintext = legacy.decrypt_content(urk, ciphertext, old_nonce)
                old_nonce = secrets.token_bytes(12)
                old_ciphertext = AESGCM(legacy.hkdf(urk, None, b"onememory:data:v1")).encrypt(old_nonce, plaintext, None).hex()
                backup.execute("UPDATE memories SET ciphertext=?,nonce=?,embedding_enc='' WHERE id=?", (old_ciphertext, old_nonce.hex(), memory_id))
                backup.execute("UPDATE core_artifacts SET source=? WHERE memory_id=?", (old_ciphertext, memory_id))
        backup.close()
        original.close()
        original_source_session = {"user": "synthetic", "addr": addr, "token": "synthetic-token", "vault_version": 2,
                                   **{k: v for k, v in v2.items() if k != "version"},
                                   "super": old_super, "pass": "synthetic-password"}
        source_session = source / "session.json"
        source_session.write_text(json.dumps(original_source_session), encoding="utf-8")
        source_session.chmod(0o600)
        (source / "client.json").write_text(json.dumps({"data_dir": str(source)}), encoding="utf-8")
        if (root / "core-index").is_dir():
            shutil.copytree(root / "core-index", source / "core-index")
        source_before = legacy.digest(source_database), source_session.read_bytes()
        alias = "legacy-" + hashlib.sha256(str(source.resolve()).replace("\\", "/").encode()).hexdigest()[:16]
        for slot in ("super", "pass"):
            migration_keys.reserve("rsrs", slot + ":" + alias)
        discovered = json.loads(cli("--json", "migrate").stdout)["details"]["profiles"]
        candidates = [row for row in discovered if Path(row["source"]).resolve() == source.resolve()]
        require(len(candidates) == 1, "original_profile_not_discovered")
        result = json.loads(cli("--json", "migrate", "--source", candidates[0]["source_id"], "--account", "recovered-original").stdout)["summary"]
        require(result["state"] == "migrated", "original_profile_not_migrated")
        restored_root = Path(result["dir"])
        require((legacy.digest(source_database), source_session.read_bytes()) == source_before, "original_source_changed")
        require(session.read_bytes() == before, "inconsistent_profile_overwritten")
        restored_session = json.loads((restored_root / "session.json").read_text())
        require(restored_session["vault_version"] == 2 and restored_session["wrapped_urk"].startswith(legacy.PREFIX), "original_factors_not_recovered")
        with sqlite3.connect(restored_root / "rsrs.db") as restored:
            restored_rows = restored.execute("SELECT id,ciphertext,nonce FROM memories ORDER BY id").fetchall()
        require(len(restored_rows) == len(original_rows) and all(ciphertext.startswith(legacy.PREFIX) for _, ciphertext, _ in restored_rows), "full_library_namespace_not_migrated")
        require([legacy.decrypt_content(urk, ciphertext, nonce) for _, ciphertext, nonce in restored_rows]
                == [legacy.decrypt_content(urk, ciphertext, nonce) for _, ciphertext, nonce in original_rows], "original_plaintext_not_recovered")
        env["RSRS_DATA_DIR"] = str(restored_root)
        cli(*migration)
        require(state["vault"]["version"] == 2 and ciphertexts() == original_rows, "DEV4_recovery_failed")
        report["cases"]["pre_journal_DEV4_recovery"] = {"passed": True, "wrong_code_rejected": True,
            "inconsistent_factors_rejected": True, "public_original_profile_migration": True,
            "full_library_reencrypted": True, "original_source_preserved": True,
            "original_factors_preserved": True, "requires_original_source": True}
        report["passed"] = True
    finally:
        release.set()
        if child is not None and child.poll() is None:
            child.kill()
            child.communicate(timeout=15)
        stopped = subprocess.run([str(args.binary), "--runtime-internal", "--stop"], env=env, capture_output=True, timeout=60)
        report["runtime_cleanup"] = {"passed": stopped.returncode in (0, 2)}
        if keys:
            # This authenticated private collection started empty. Delete only
            # synthetic login aliases produced by this fixture's own children.
            for item in keys.collection.get_all_items():
                attributes = item.get_attributes()
                require(attributes.get("service") == "rsrs" and re.fullmatch(r"(?:super|pass):(?:login-[a-f0-9]{32}|legacy-[a-f0-9]{16})", attributes.get("username", "")), "unexpected_private_credential")
                item.delete()
            require(not list(keys.collection.get_all_items()), "native_fixture_cleanup_failed")
            report["native_cleanup"] = keys.cleanup()
        elif migration_keys:
            report["native_cleanup"] = migration_keys.cleanup()
        server.shutdown()
        server.server_close()
        (args.root / "interruption-coverage.json").write_text(json.dumps(report, indent=2) + "\n")
    require(report["runtime_cleanup"]["passed"], "owned_runtime_cleanup_failed")
    if migration_keys or keys:
        require(report["native_cleanup"]["passed"], "native_fixture_cleanup_failed")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
