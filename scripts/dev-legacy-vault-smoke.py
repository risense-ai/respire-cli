#!/usr/bin/env python3
"""CI-only synthetic legacy wraps, real CLI upgrade and new-device decryption."""
import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import subprocess
import sys
import urllib.error
import urllib.request

UPSTREAM = "https://api.dev.rsrs.rs"
REQUIRED = ("model_cpu_real", "local_v1_upgrade", "cloud_v2_recovery_upgrade", "cloud_v3_secret_key_recovery_upgrade")
MODEL_HASHES = {
    "onnx/model.onnx": "5e5619f7cca7380b824d329c157dba10bee7cc00d0c139e82fdb7906051b8e4f",
    "tokenizer.json": "7dfbf1966ebf99d471c3796e9b457329d2b2182b817e144f1e904b957745c839",
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


def v4_kek(code, salt):
    entropy = bytes.fromhex(code.strip().removeprefix("A3-").replace("-", ""))
    require(len(entropy) == 18, "recovery_code_invalid")
    return hkdf(entropy, bytes.fromhex(salt), b"onememory:kek:v4")


def legacy_kek(version, password, account_secret, salt):
    if version == 1:
        from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
        # Public crypto::derive_kek uses Argon2::default (v19, m19456, t2, p1).
        intermediate = Argon2id(salt=bytes.fromhex(salt), length=32, iterations=2,
            lanes=1, memory_cost=19456).derive(password.encode())
    else:
        intermediate = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 210000, 32)
    return intermediate if version == 2 else hkdf(intermediate, account_secret.encode(), b"onememory:kek:v1")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Smoke:
    def __init__(self, args):
        self.args = args
        self.root = args.root
        self.model = self.root / "models/bge-base-zh-v1.5"
        self.root.mkdir()
        self.base_env = {k: v for k, v in os.environ.items()
            if not k.startswith(("ONEMEMORY_", "RESPIRE_", "XDG_", "DS_", "JEV_"))
            and not k.endswith(("_TOKEN", "_API_KEY")) and "TEST_MODE" not in k
            and k not in ("HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "DBUS_SESSION_BUS_ADDRESS",
                "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")}
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        self.accounts = []
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
            ONEMEMORY_DATA_DIR=str(path / "library"), ONEMEMORY_BIN_DIR=str(path / "bin"),
            ONEMEMORY_MODEL_DIR=str(self.model), ONEMEMORY_ENGINE="cpu", ONEMEMORY_NO_AUTOSYNC="1",
            DBUS_SESSION_BUS_ADDRESS="unix:path=" + str(path / "tmp/missing-keyring.sock"))
        if user:
            self.write_session(env, {"user": user})
        return env

    def cli(self, env, *args, timeout=180):
        output = subprocess.run([str(self.args.binary), "--direct", "--json", *args],
            cwd=self.root, env=env, capture_output=True, timeout=timeout)
        require(output.returncode == 0, "cli_failed_" + args[0])
        try:
            value = json.loads(output.stdout)
        except (ValueError, UnicodeError):
            raise RuntimeError("invalid_cli_json_" + args[0]) from None
        require(not value.get("errors") and value.get("status") not in ("error", "failed"), "cli_error_" + args[0])
        return value

    def session(self, env):
        return json.loads((Path(env["ONEMEMORY_DATA_DIR"]) / "session.json").read_text())

    def write_session(self, env, value):
        path = Path(env["ONEMEMORY_DATA_DIR"]) / "session.json"
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
        user, password = "ci-vault-" + secrets.token_hex(8), "-" + secrets.token_urlsafe(32)
        account = {"user": user, "token": None, "confirmed": False}
        self.accounts.append(account)
        self.report["cloud_cleanup"]["remaining_users"].append(user)
        self.save()
        registered = self.cli(env, "register", "--addr", UPSTREAM, "--user", user, "--pass=" + password)
        session = self.session(env)
        require(registered["summary"].get("ok") is True and registered["summary"].get("user") == user
            and session.get("user") == user and session.get("addr") == UPSTREAM
            and isinstance(session.get("token"), str) and bool(session["token"]), "registered_identity_mismatch")
        account.update(token=session["token"], confirmed=True)
        original_code = registered["summary"].get("super")
        require(isinstance(original_code, str) and bool(original_code), "registered_super_missing")
        env["ONEMEMORY_SUPER"] = original_code
        vault = self.api(account, "GET", "/api/self/vault")
        urk = AESGCM(v4_kek(original_code, vault["kdf_salt"])).decrypt(
            bytes.fromhex(vault["urk_nonce"]), bytes.fromhex(vault["wrapped_urk"]), None)
        require(len(urk) == 32, "original_urk_invalid")
        plaintext = f"Synthetic legacy version {version} preserves this original encrypted content."
        title = f"CI legacy vault {version}"
        self.cli(env, "remember", plaintext, "--title", title, "--force", "--importance", "important")
        db_path = Path(env["ONEMEMORY_DATA_DIR"]) / "onememory.db"
        with sqlite3.connect(db_path.as_uri() + "?mode=ro", uri=True) as db:
            entries = db.execute("SELECT id,ciphertext,nonce FROM memories WHERE title=? AND deleted=0", (title,)).fetchall()
        require(len(entries) == 1, "legacy_entry_not_unique")
        memory_id, ciphertext, item_nonce = entries[0]
        self.cli(env, "sync", timeout=180)
        salt, nonce = secrets.token_bytes(16).hex(), secrets.token_bytes(12)
        legacy_pass = password if version == 1 else secrets.token_urlsafe(32)
        secret = secrets.token_hex(32) if version == 1 else original_code
        wrapped = AESGCM(legacy_kek(version, legacy_pass, secret, salt)).encrypt(nonce, urk, None).hex()
        # The server accepts vault versions 2..4; v1 is a local-session compatibility path.
        cloud_version = max(2, version)
        old_vault = {"version": cloud_version, "kdf_salt": salt, "wrapped_urk": wrapped, "urk_nonce": nonce.hex()}
        if version == 1:
            rejected, _ = self.request(account, "POST", "/api/self/vault", {**old_vault, "version": 1})
            require(rejected == 400, "unsupported_cloud_v1_not_rejected")
        require(self.api(account, "POST", "/api/self/vault", old_vault).get("ok") is True, "legacy_vault_not_written")
        fetched = self.api(account, "GET", "/api/self/vault")
        require(all(fetched.get(k) == v for k, v in old_vault.items()), "legacy_vault_not_read_back")
        if version == 1:
            session.update(vault_version=1, kdf_salt=salt, wrapped_urk=wrapped, urk_nonce=nonce.hex(), secret=secret)
            session.pop("secret_key", None)
            self.write_session(env, session)
            upgraded_env = env
        else:
            upgraded_env = self.env(f"v{version}-legacy-recovery", user)
        command = ["login", "--addr", UPSTREAM, "--user", user, "--pass=" + password]
        if version != 1:
            command += ["--super=" + legacy_pass]
        if version == 3:
            command += ["--secret-key=" + secret]
        result = self.cli(upgraded_env, *command)
        new_code = secret if version == 3 else result["summary"].get("super_issued")
        require(isinstance(new_code, str) and bool(new_code), "upgraded_recovery_code_missing")
        upgraded_env["ONEMEMORY_SUPER"] = new_code
        upgraded = self.session(upgraded_env)
        require(upgraded.get("vault_version") == 4, "local_vault_not_upgraded")
        account["token"] = upgraded["token"]
        new_vault = self.api(account, "GET", "/api/self/vault")
        require(new_vault.get("version") == 4, "cloud_vault_not_upgraded")
        recovered = AESGCM(v4_kek(new_code, new_vault["kdf_salt"])).decrypt(
            bytes.fromhex(new_vault["urk_nonce"]), bytes.fromhex(new_vault["wrapped_urk"]), None)
        require(recovered == urk, "upgrade_changed_urk")
        self.cli(upgraded_env, "sync")
        self.read_entry(upgraded_env, memory_id, plaintext)
        with sqlite3.connect(db_path.as_uri() + "?mode=ro", uri=True) as db:
            original = db.execute("SELECT ciphertext,nonce FROM memories WHERE id=?", (memory_id,)).fetchone()
        require(original == (ciphertext, item_nonce), "upgrade_changed_original_ciphertext")
        final_env = self.env(f"v{version}-new-device", user)
        final_env["ONEMEMORY_SUPER"] = new_code
        self.cli(final_env, "login", "--addr", UPSTREAM, "--user", user, "--pass=" + password, "--super=" + new_code)
        final_session = self.session(final_env)
        require(final_session.get("user") == user and final_session.get("addr") == UPSTREAM
            and isinstance(final_session.get("token"), str) and bool(final_session["token"]),
            "new_device_session_identity_mismatch")
        account["token"] = final_session["token"]
        self.cli(final_env, "sync")
        self.read_entry(final_env, memory_id, plaintext)
        final_db = Path(final_env["ONEMEMORY_DATA_DIR"]) / "onememory.db"
        with sqlite3.connect(final_db.as_uri() + "?mode=ro", uri=True) as db:
            downloaded = db.execute("SELECT ciphertext,nonce FROM memories WHERE id=?", (memory_id,)).fetchone()
        require(downloaded == (ciphertext, item_nonce), "upgrade_changed_cloud_ciphertext")
        self.passed(REQUIRED[version], local_legacy_version=version, cloud_fixture_version=cloud_version,
            resulting_version=4, urk_preserved=True, original_ciphertext_preserved=True,
            old_content_decrypted=True, new_device_v4_decrypted=True,
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
        env = self.env("model-probe")
        output = subprocess.run([str(self.args.binary), "--version"], env=env, capture_output=True, timeout=20)
        require(output.returncode == 0 and re.search(r"(?<!\S)" + re.escape(self.args.version) + r"(?!\S)", output.stdout.decode()), "binary_version_mismatch")
        self.cli(env, "model", "install-bge", timeout=900)
        require(all(digest(self.model / p) == h for p, h in MODEL_HASHES.items()), "model_hash_mismatch")
        self.cli(env, "model", "engine", "cpu")
        probe = self.cli(env, "model", "probe", "--model", "legacy", "--text", "Legacy recovery CPU probe")["summary"]
        require(probe.get("ready") is True and probe.get("dimensions") == 768
            and str(probe.get("selected")).lower() == "cpu", "real_cpu_probe_failed")
        self.passed("model_cpu_real", dimensions=768, model_hashes=MODEL_HASHES)
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
        smoke.report["missing_cases"] = [case for case in REQUIRED if case not in smoke.report["cases"]]
        if not smoke.report["cloud_cleanup"]["passed"]:
            smoke.report["status"] = "failed"
        smoke.report["passed"] = smoke.report["status"] == "passed" and not smoke.report["missing_cases"] \
            and smoke.report["cloud_cleanup"]["passed"]
        smoke.save()
    print(json.dumps({"status": smoke.report["status"], "passed": len(smoke.report["cases"]),
        "required": len(REQUIRED), "report": str(smoke.root / "legacy-vault-coverage.json")}))
    return 0 if smoke.report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
