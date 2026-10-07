#!/usr/bin/env python3
"""CI-only synthetic legacy wraps, real CLI upgrade and new-device decryption."""
import argparse
import hashlib
import hmac
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import socket
import sqlite3
import subprocess
import sys
import urllib.error
import urllib.request

UPSTREAM = "https://api.dev.rsrs.rs"
REQUIRED = ("model_cpu_real", "local_v1_upgrade", "cloud_v2_recovery_upgrade", "cloud_v3_secret_key_recovery_upgrade")
MODEL_HASHES = {
    "onnx/model_quantized.onnx": "0826f8c1ab9edf1801db86c61919d4d108e8bfc0b809ec823ad366882ff0b77d",
    "tokenizer.json": "6710678b12670bc442b99edc952c4d996ae309a7020c1fa0096dd245c2faf790",
}


def require(value, code):
    if not value:
        raise RuntimeError(code)


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def hkdf(ikm, salt, info, length=32):
    prk = hmac.new(salt if salt is not None else bytes(32), ikm, hashlib.sha256).digest()
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()[:length]


PREFIX = "rsrs:v1:"


def encrypted_bytes(value):
    return bytes.fromhex(value.removeprefix(PREFIX))


def v4_kek(code, salt, wrapped=""):
    entropy = bytes.fromhex(code.strip().removeprefix("A3-").replace("-", ""))
    require(len(entropy) == 18, "recovery_code_invalid")
    info = b"rsrs:kek:v4" if wrapped.startswith(PREFIX) else b"onememory:kek:v4"
    return hkdf(entropy, bytes.fromhex(salt), info)


def legacy_kek(version, password, account_secret, salt, current=False):
    if version == 1:
        from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
        # Public crypto::derive_kek uses Argon2::default (v19, m19456, t2, p1).
        intermediate = Argon2id(salt=bytes.fromhex(salt), length=32, iterations=2,
            lanes=1, memory_cost=19456).derive(password.encode())
    else:
        intermediate = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 210000, 32)
    info = b"rsrs:kek:v1" if current else b"onememory:kek:v1"
    return intermediate if version == 2 else hkdf(intermediate, account_secret.encode(), info)


def decrypt_content(urk, ciphertext, nonce):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    info = b"rsrs:data:v1" if ciphertext.startswith(PREFIX) else b"onememory:data:v1"
    return AESGCM(hkdf(urk, None, info)).decrypt(bytes.fromhex(nonce), encrypted_bytes(ciphertext), None)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Smoke:
    def __init__(self, args):
        self.args = args
        self.root = args.root
        self.model = self.root / "models/bge-m3"
        self.root.mkdir()
        self.base_env = {k: v for k, v in os.environ.items()
            if not k.startswith(("RSRS_", "ONEMEMORY_", "RESPIRE_", "XDG_", "DS_", "JEV_"))
            and not k.endswith(("_TOKEN", "_API_KEY")) and "TEST_MODE" not in k
            and k not in ("HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "DBUS_SESSION_BUS_ADDRESS",
                "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")}
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        self.accounts = []
        self.keys = None
        self.report = {"status": "running", "source_sha": args.source_sha,
            "workflow_sha": os.environ.get("GITHUB_SHA"), "version": args.version,
            "binary_sha256": args.binary_sha256, "target": UPSTREAM, "cases": {},
            "passed": False, "required_cases": list(REQUIRED),
            "dependency": "cryptography==46.0.3", "cloud_cleanup": {"passed": False, "events": [], "remaining_users": []}}

    def env(self, name, user=None):
        path = self.root / name
        require(not path.exists(), "profile_not_fresh")
        for folder in ("home", "config", "data", "cache", "tmp", "library", "bin"):
            (path / folder).mkdir(parents=True)
        env = dict(self.base_env)
        env.update(HOME=str(path / "home"), USERPROFILE=str(path / "home"),
            APPDATA=str(path / "config"), LOCALAPPDATA=str(path / "data"),
            XDG_CONFIG_HOME=str(path / "config"), XDG_DATA_HOME=str(path / "data"),
            XDG_CACHE_HOME=str(path / "cache"), TMPDIR=str(path / "tmp"),
            RSRS_DATA_DIR=str(path / "library"), RSRS_BIN_DIR=str(path / "bin"),
            RSRS_M3_DIR=str(self.model), RSRS_ENGINE="cpu", RSRS_NO_AUTOSYNC="1",
            DBUS_SESSION_BUS_ADDRESS="unix:path=" + str(path / "tmp/missing-keyring.sock"))
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            env['RSRS_RPC_PORT'] = str(listener.getsockname()[1])
        if user:
            self.write_session(env, {"user": user})
        if self.keys is not None:
            self.keys.configure_env(env)
        return env

    def cli(self, env, *args, timeout=180):
        try:
            output = subprocess.run([str(self.args.binary), "--direct", "--json", *args],
                cwd=self.root, env=env, capture_output=True, timeout=timeout)
        finally:
            # Login and automatic indexing can start this fixture's runtime.
            # Release it before subsequent direct database consumers.
            stopped = subprocess.run([str(self.args.binary), '--runtime-internal', '--stop'],
                cwd=self.root, env=env, capture_output=True, timeout=60)
            require(stopped.returncode in (0, 2), 'owned_runtime_stop_failed')
        require(output.returncode == 0, "cli_failed_" + args[0])
        try:
            value = json.loads(output.stdout)
        except (ValueError, UnicodeError):
            raise RuntimeError("invalid_cli_json_" + args[0]) from None
        require(not value.get("errors") and value.get("status") not in ("error", "failed"), "cli_error_" + args[0])
        return value

    def session(self, env):
        return json.loads((Path(env["RSRS_DATA_DIR"]) / "session.json").read_text())

    def write_session(self, env, value):
        path = Path(env["RSRS_DATA_DIR"]) / "session.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        path.chmod(0o600)

    def request(self, account, method, path, body=None):
        require(account["confirmed"] and account["token"], "account_identity_not_confirmed")
        encoded = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(UPSTREAM + path, encoded,
            {"Authorization": "Bearer " + account["token"], "Content-Type": "application/json"}, method=method)
        try:
            response = self.opener.open(request, timeout=45)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            raw = response.read(1024 * 1024 + 1)
            require(len(raw) <= 1024 * 1024, "api_response_too_large")
            return response.code, json.loads(raw)

    def api(self, account, method, path, body=None):
        status, value = self.request(account, method, path, body)
        require(status == 200, "dev_api_failed_" + method + "_" + path.replace("/", "_"))
        return value

    def save(self):
        (self.root / "legacy-vault-coverage.json").write_text(json.dumps(self.report, indent=2) + "\n", encoding="utf-8")

    def passed(self, name, **facts):
        self.report["cases"][name] = {"status": "passed", "passed": True, **facts}
        self.save()

    def read_entry(self, env, memory_id, plaintext):
        result = self.cli(env, "show", memory_id)
        require(plaintext in json.dumps(result), "old_ciphertext_not_decrypted")

    def run_version(self, version):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        env = self.env(f"v{version}-original")
        user, password = "ci-migrate-" + secrets.token_hex(8), "ci-" + secrets.token_urlsafe(32)
        for slot in ("super:", "pass:"):
            self.keys.reserve("rsrs", slot + user)
        account = {"user": user, "token": None, "confirmed": False}
        self.accounts.append(account)
        self.report["cloud_cleanup"]["remaining_users"].append(user)
        self.save()
        registered = self.cli(env, "register", "--addr", UPSTREAM, "--user", user, "--pass=" + password)
        session = self.session(env)
        require(registered["summary"].get("ok") is True and registered["summary"].get("user") == user
            and session.get("user") == user and session.get("addr") == UPSTREAM and bool(session.get("token")),
            "registered_identity_mismatch")
        account.update(token=session["token"], confirmed=True)
        code = registered["summary"].get("super")
        require(isinstance(code, str) and bool(code), "registered_super_missing")
        env["RSRS_SUPER"] = code
        vault = self.api(account, "GET", "/api/self/vault")
        urk = AESGCM(v4_kek(code, vault["kdf_salt"], vault["wrapped_urk"])).decrypt(
            bytes.fromhex(vault["urk_nonce"]), encrypted_bytes(vault["wrapped_urk"]), None)
        require(len(urk) == 32, "original_urk_invalid")
        plaintext = f"Synthetic legacy version {version} preserves this original encrypted content."
        title = f"CI legacy vault {version}"
        self.cli(env, "remember", plaintext, "--title", title, "--force", "--importance", "important")
        self.cli(env, "sync", timeout=180)
        database = Path(env["RSRS_DATA_DIR"]) / "rsrs.db"
        with sqlite3.connect(database) as db:
            entries = db.execute("SELECT id,ciphertext,nonce FROM memories WHERE title=? AND deleted=0", (title,)).fetchall()
            require(len(entries) == 1, "legacy_entry_not_unique")
            memory_id, ciphertext, item_nonce = entries[0]
            payload = decrypt_content(urk, ciphertext, item_nonce)
            item_nonce = secrets.token_bytes(12).hex()
            ciphertext = AESGCM(hkdf(urk, None, b"onememory:data:v1")).encrypt(bytes.fromhex(item_nonce), payload, None).hex()
            db.execute("UPDATE memories SET ciphertext=?,nonce=? WHERE id=?", (ciphertext, item_nonce, memory_id))
            db.execute("UPDATE core_artifacts SET source=? WHERE memory_id=?", (ciphertext, memory_id))
            db.execute("PRAGMA wal_checkpoint(TRUNCATE)") if not db.in_transaction else None
        # Close SQLite before relocating this owned old-format source.
        db.close()
        source = Path(env["HOME"]) / ".onememory"
        Path(env["RSRS_DATA_DIR"]).rename(source)
        (source / "rsrs.db").rename(source / "onememory.db")
        env["RSRS_DATA_DIR"] = str(source)
        salt, nonce = secrets.token_bytes(16).hex(), secrets.token_bytes(12)
        original_super = code if version == 1 else secrets.token_urlsafe(32)
        secret = secrets.token_hex(32)
        wrapped = AESGCM(legacy_kek(version, password if version == 1 else original_super, secret, salt)).encrypt(nonce, urk, None).hex()
        old_vault = {"version": version, "kdf_salt": salt, "wrapped_urk": wrapped, "urk_nonce": nonce.hex()}
        if version == 1:
            rejected, _ = self.request(account, "POST", "/api/self/vault", old_vault)
            require(rejected == 400, "unsupported_cloud_v1_not_rejected")
        else:
            require(self.api(account, "POST", "/api/self/vault", old_vault).get("ok") is True, "legacy_vault_not_written")
            require(all(self.api(account, "GET", "/api/self/vault").get(k) == v for k, v in old_vault.items()),
                "legacy_vault_not_read_back")
        session.update({"vault_version": version, "kdf_salt": salt, "wrapped_urk": wrapped, "urk_nonce": nonce.hex(),
            "pass": password, "super": original_super})
        session.pop("crypto_namespace", None)
        session.pop("keyring_account", None)
        if version == 1:
            session["secret"] = secret
        elif version == 3:
            session["secret_key"] = secret
        self.write_session(env, session)
        source_config_path = source / "client.json"
        source_config = json.loads(source_config_path.read_text()) if source_config_path.exists() else {}
        source_config["data_dir"] = str(source)
        source_config_path.write_text(json.dumps(source_config), encoding="utf-8")
        original_session = (source / "session.json").read_bytes()
        original_database = digest(source / "onememory.db")
        alias = "legacy-" + hashlib.sha256(str(source.resolve()).encode()).hexdigest()[:16]
        for slot in ("super:", "pass:"):
            self.keys.reserve("rsrs", slot + alias)
        migration_env = dict(env, RSRS_SUPER=original_super)
        migration_env.pop("RSRS_DATA_DIR")
        candidates = self.cli(migration_env, "migrate")["details"]["profiles"]
        rows = [row for row in candidates if Path(row["source"]).resolve() == source.resolve()]
        require(len(rows) == 1, "legacy_source_not_unique")
        result = self.cli(migration_env, "migrate", "--source", rows[0]["source_id"], "--account", rows[0]["account"])
        require(result["summary"].get("state") == "migrated", "full_migration_not_published")
        destination = Path(result["summary"]["dir"])
        upgraded_env = dict(env, RSRS_DATA_DIR=str(destination), RSRS_SUPER=original_super)
        upgraded = self.session(upgraded_env)
        require(upgraded["vault_version"] == version and upgraded["wrapped_urk"].startswith(PREFIX),
            "migration_changed_original_factors")
        self.read_entry(upgraded_env, memory_id, plaintext)
        with sqlite3.connect((destination / "rsrs.db").as_uri() + "?mode=ro", uri=True) as db:
            converted = db.execute("SELECT ciphertext,nonce FROM memories WHERE id=?", (memory_id,)).fetchone()
        require(converted[0].startswith(PREFIX) and converted != (ciphertext, item_nonce)
            and decrypt_content(urk, *converted) == payload, "full_migration_not_reencrypted")
        require(self.keys.read("rsrs", "pass:" + alias) == password, "original_password_not_retained")
        if version != 1:
            require(self.keys.read("rsrs", "super:" + alias) == original_super, "original_super_not_retained")
            result = self.cli(upgraded_env, "migrate", "--vault", "--addr", UPSTREAM, "--user", user,
                "--pass=" + password, "--super=" + original_super)
            require(result["summary"].get("super_issued") is None, "migration_generated_replacement_super")
            account["token"] = self.session(upgraded_env)["token"]
            published = self.api(account, "GET", "/api/self/vault")
            require(published["version"] == version and published["wrapped_urk"].startswith(PREFIX), "cloud_factors_changed")
            recovered = AESGCM(legacy_kek(version, original_super, secret, published["kdf_salt"], current=True)).decrypt(
                bytes.fromhex(published["urk_nonce"]), encrypted_bytes(published["wrapped_urk"]), None)
            require(recovered == urk, "migration_changed_urk")
            self.cli(upgraded_env, "sync")
            final_env = self.env(f"v{version}-new-device", user)
            final_env["RSRS_SUPER"] = original_super
            if version == 3:
                # Explicitly restore the original second recovery factor.
                self.write_session(final_env, {"user": user, "secret_key": secret})
            self.cli(final_env, "login", "--interactive", "--addr", UPSTREAM, "--user", user,
                "--pass=" + password, "--super=" + original_super)
            account["token"] = self.session(final_env)["token"]
            self.cli(final_env, "sync")
            self.read_entry(final_env, memory_id, plaintext)
            with sqlite3.connect((Path(final_env["RSRS_DATA_DIR"]) / "rsrs.db").as_uri() + "?mode=ro", uri=True) as db:
                require(db.execute("SELECT ciphertext,nonce FROM memories WHERE id=?", (memory_id,)).fetchone() == converted,
                    "new_device_ciphertext_differs")
        require((source / "session.json").read_bytes() == original_session
            and digest(source / "onememory.db") == original_database, "original_source_changed")
        self.passed(REQUIRED[version], local_legacy_version=version, resulting_version=version,
            urk_preserved=True, original_super_preserved=True, original_source_preserved=True,
            ciphertext_reencrypted=True, old_content_decrypted=True, new_device_decrypted=version != 1,
            secret_key_recovery=version == 3, cloud_v1_recovery_supported=False if version == 1 else None,
            cloud_v1_write_rejected=version == 1)

    def cleanup(self):
        cleanup = self.report["cloud_cleanup"]
        for account in self.accounts:
            event = {"user": account["user"], "passed": False}
            try:
                require(account["confirmed"], "registration_outcome_unconfirmed")
                value = self.api(account, "POST", "/api/self/purge", {"confirm": account["user"]})
                require(value.get("purged") is True and value.get("user") == account["user"], "self_purge_not_confirmed")
                status, _ = self.request(account, "GET", "/api/self")
                require(status == 401, "purged_token_still_accepted")
                cleanup["remaining_users"].remove(account["user"])
                event.update(passed=True, old_token_rejected=True)
            except Exception as error:
                event["code"] = str(error) if isinstance(error, RuntimeError) else type(error).__name__
            cleanup["events"].append(event)
        cleanup["passed"] = not cleanup["remaining_users"]

    def run(self):
        import cryptography
        require(cryptography.__version__ == "46.0.3", "cryptography_version_not_pinned")
        spec = importlib.util.spec_from_file_location("legacy_vault_keyring", Path(__file__).with_name("dev-migration-keyring.py"))
        backend = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(backend)
        self.keys = backend.create(self.root / "keyring-home")
        env = self.env("model-probe")
        output = subprocess.run([str(self.args.binary), "--version"], env=env, capture_output=True, timeout=20)
        require(output.returncode == 0 and re.search(r"(?<!\S)" + re.escape(self.args.version) + r"(?!\S)", output.stdout.decode()), "binary_version_mismatch")
        self.cli(env, "model", "install-m3", timeout=900)
        require(all(digest(self.model / p) == h for p, h in MODEL_HASHES.items()), "model_hash_mismatch")
        self.cli(env, "model", "engine", "cpu")
        probe = self.cli(env, "model", "probe", "--model", "m3", "--text", "Legacy recovery CPU probe")["summary"]
        require(probe.get("ready") is True and probe.get("dimensions") == 1024
            and str(probe.get("selected")).lower() == "cpu", "real_cpu_probe_failed")
        self.passed("model_cpu_real", dimensions=1024, model_hashes=MODEL_HASHES)
        for version in (1, 2, 3):
            self.run_version(version)
        self.report["status"] = "passed"


def main():
    require(os.environ.get("GITHUB_ACTIONS") == "true", "github_actions_required")
    require(os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted" and sys.platform.startswith("linux"), "disposable_linux_hosted_runner_required")
    parser = argparse.ArgumentParser()
    for name in ("binary", "root"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("binary-sha256", "source-sha", "version"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    require(re.fullmatch(r"[0-9a-f]{64}", args.binary_sha256), "binary_sha_invalid")
    require(re.fullmatch(r"[0-9a-f]{40}", args.source_sha) and args.source_sha == os.environ.get("CLI_SHA"), "verified_artifact_source_sha_mismatch")
    require(args.version and not any(c.isspace() for c in args.version), "version_invalid")
    require(args.binary.is_absolute() and args.binary.is_file() and digest(args.binary) == args.binary_sha256, "binary_hash_mismatch")
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
        smoke.cleanup()
        if smoke.keys is not None:
            try:
                smoke.report["keyring_cleanup"] = smoke.keys.cleanup()
            except Exception as error:
                smoke.report["keyring_cleanup"] = {"passed": False, "failure_code": type(error).__name__}
        smoke.report["missing_cases"] = [case for case in REQUIRED if case not in smoke.report["cases"]]
        if not smoke.report["cloud_cleanup"]["passed"]:
            smoke.report["status"] = "failed"
        smoke.report["passed"] = smoke.report["status"] == "passed" and not smoke.report["missing_cases"] \
            and smoke.report["cloud_cleanup"]["passed"] and smoke.report.get("keyring_cleanup", {}).get("passed") is True
        smoke.save()
    print(json.dumps({"status": smoke.report["status"], "passed": len(smoke.report["cases"]),
        "required": len(REQUIRED), "report": str(smoke.root / "legacy-vault-coverage.json")}))
    return 0 if smoke.report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
