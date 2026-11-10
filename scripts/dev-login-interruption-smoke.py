#!/usr/bin/env python3
"""Real Linux CLI SIGINT recovery; only synthetic accounts and loopback HTTP."""
from native_fixture_process import install_published_runtime
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
from dev_witness_fixture import register_witness_functions, verify_fixture_witness
import subprocess
import threading
import uuid
import select
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

spec = importlib.util.spec_from_file_location("legacy", Path(__file__).with_name("dev-legacy-vault-smoke.py"))
legacy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(legacy)
require = legacy.require


def process_group_members(group):
    members = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            raw = (entry / "stat").read_text()
            fields = raw[raw.rfind(")") + 2:].split()
            if int(fields[2]) != group:
                continue
            argv = (entry / "cmdline").read_bytes().split(b"\0")
            members[int(entry.name)] = {"parent": int(fields[1]), "group": int(fields[2]),
                "session": int(fields[3]), "start_ticks": int(fields[19]), "state": fields[0],
                "control_helper": b"--host-control-internal" in argv}
        except (FileNotFoundError, ProcessLookupError):
            continue
    return members


def interrupt_owned_control(child):
    """Bind the fresh session and exact private helper before signalling; wait both."""
    members = process_group_members(child.pid)
    require(child.poll() is None and child.pid in members and os.getpgid(child.pid) == child.pid
            and os.getsid(child.pid) == child.pid, "interruption_session_not_owned")
    require(members[child.pid]["parent"] == os.getpid(), "interruption_child_not_owned")
    helpers = [pid for pid, row in members.items() if row["control_helper"]]
    require(len(helpers) == 1 and members[helpers[0]]["parent"] == child.pid,
            "interruption_control_helper_not_bound")
    require(all(row["session"] == child.pid and (pid == child.pid or row["parent"] == child.pid)
                for pid, row in members.items()), "interruption_group_has_unbound_member")
    handles = []
    completed = False
    child._fixture_pidfds = handles
    try:
        for pid in members:
            handles.append(os.pidfd_open(pid))
        require({pid: {k: v for k, v in row.items() if k != "state"}
                 for pid, row in process_group_members(child.pid).items()}
                == {pid: {k: v for k, v in row.items() if k != "state"}
                    for pid, row in members.items()}, "interruption_group_changed")
        os.killpg(child.pid, signal.SIGINT)
        child.communicate(timeout=15)  # Reap our direct CLI child.
        require(child.returncode == -signal.SIGINT, "owned_child_not_interrupted")
        # Control helpers are grandchildren, not waitpid children. pidfd readiness
        # proves their exit even if the system reaper has not collected the zombie.
        poller = select.poll()
        for handle in handles:
            poller.register(handle, select.POLLIN)
        exited = {handle for handle, events in poller.poll(15000) if events & select.POLLIN}
        # The CLI may report first; individually wait each still-unobserved helper.
        for handle in set(handles) - exited:
            waiter = select.poll()
            waiter.register(handle, select.POLLIN)
            require(any(events & select.POLLIN for _, events in waiter.poll(15000)),
                    "interrupted_control_helper_still_running")
        require(all(row["state"] == "Z" for row in process_group_members(child.pid).values()),
                "interrupted_group_still_running")
        completed = True
        return {"group": child.pid, "members": members, "cli_reaped": True, "helper_exit_confirmed": True}
    finally:
        if completed:
            for handle in handles:
                os.close(handle)
            child._fixture_pidfds = []


def stop_owned_control(child):
    """Failure teardown uses lifetime-bound pidfds, never a recycled numeric group."""
    handles = getattr(child, "_fixture_pidfds", [])
    if not handles:
        members = process_group_members(child.pid)
        if members:
            require(child.poll() is None and child.pid in members
                    and members[child.pid]["parent"] == os.getpid()
                    and all(row["session"] == child.pid and (pid == child.pid or row["parent"] == child.pid)
                            for pid, row in members.items()), "cleanup_process_lifetime_unproven")
            for pid, row in members.items():
                handle = os.pidfd_open(pid)
                handles.append(handle)
                observed = process_group_members(child.pid).get(pid)
                require(observed is not None and observed["start_ticks"] == row["start_ticks"],
                        "cleanup_process_identity_changed")
    try:
        for handle in handles:
            try:
                signal.pidfd_send_signal(handle, signal.SIGKILL)
            except ProcessLookupError:
                pass
        child.communicate(timeout=15)
        for handle in handles:
            waiter = select.poll()
            waiter.register(handle, select.POLLIN)
            require(any(events & select.POLLIN for _, events in waiter.poll(15000)),
                    "cleanup_control_helper_still_running")
        # A partial pidfd snapshot or a late helper spawn must fail closed. Do not
        # signal newly discovered numeric PIDs or release their publication barrier.
        require(all(row["state"] == "Z" for row in process_group_members(child.pid).values()),
                "cleanup_untracked_group_member")
    finally:
        for handle in handles:
            os.close(handle)
        child._fixture_pidfds = []


def original_operation(journal, root, barrier, addr):
    """Read the synthetic journal without rewriting or downgrading its ownership."""
    require(journal.get("schema_version") == 2, "operation_journal_schema_missing")
    active = journal.get("active") or {}
    operation_id = active.get("operation_id")
    require(isinstance(operation_id, str), "original_operation_missing")
    parsed = uuid.UUID(operation_id)
    require(parsed.version == 4 and str(parsed) == operation_id, "original_operation_invalid")
    records = [row for row in journal["operations"] if row["operation_id"] == operation_id]
    require(len(records) == 1, "original_operation_not_unique")
    record = records[0]
    require(record["idempotency_key"] == operation_id and record["profile"] == str(root.resolve())
            and record["root"] == str(root.resolve()) and active["alias"] == record["alias"],
            "original_operation_binding_changed")
    account = record["account"]
    login = account["login"]
    candidate = json.loads(bytes(record["candidate"]))
    require(account["user"] == "synthetic" and account["addr"] == addr
            and candidate["user"] == "synthetic" and candidate["addr"] == addr
            and candidate["token"] == "synthetic-token" and candidate["keyring_account"] == record["alias"],
            "original_account_identity_changed")
    require(not account["register"] and login["migrate_vault"]
            and record["phase"] == "awaiting_verification", "interrupted_phase_not_proven")
    require(not login["publication_done"] and not login["vault_done"] and not login["password_done"],
            "interruption_already_completed")
    require(barrier in ("before_publish", "after_publish"), "invalid_publication_barrier")
    require(login["publication_pending"] == (barrier == "after_publish")
            and login["publication_step"] == ("vault" if barrier == "after_publish" else None),
            "publication_checkpoint_not_proven")
    return record


def account_recovery_flags(action, record):
    require(action in ("account-result", "account-rollback"), "invalid_recovery_action")
    return ["--json", "runtime", action, "--operation-id", record["operation_id"],
            "--source-profile", record["profile"], *(["--confirm"] if action == "account-rollback" else [])]


def terminal_operation(journal, record, outcome):
    require(journal.get("schema_version") == 2 and journal.get("active") is None,
            "operation_recovery_not_retired")
    rows = [row for row in journal["operations"] if row["operation_id"] == record["operation_id"]]
    require(len(rows) == 1 and rows[0]["phase"] == outcome
            and all(rows[0][key] == record[key] for key in ("idempotency_key", "root", "profile", "alias")),
            "original_terminal_receipt_missing")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("binary", "root", "model-dir"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("binary-sha256", "source-sha", "version"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--native-credentials", action="store_true")
    args = parser.parse_args()
    require(os.name == "posix" and Path("/proc/self/stat").is_file() and hasattr(os, "pidfd_open"),
            "SIGINT_fixture_requires_linux_pidfd")
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
    state = {"vault": v4, "auth_salt": old_auth_salt, "gets": 0, "posts": 0, "logins": 0, "password_posts": 0, "barrier": None}
    reached, release = threading.Event(), threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def reply(self, value, status=200):
            body = json.dumps(value).encode()
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass  # Expected: the test terminates its own waiting CLI.

        def do_POST(self):
            if state.get("barrier_failed"):
                self.send_error(503)
                return
            data = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
            if self.path == "/login":
                state["logins"] += 1
                self.reply({"user": "synthetic", "token": "synthetic-token", "session_id": "fixture"})
            elif self.path == "/api/self/vault":
                state["vault"] = data
                state["posts"] += 1
                if state["barrier"] == "after_publish":
                    reached.set()
                    if not release.wait(120):
                        # Never let a timed-out barrier authorize further effects.
                        # Latch all fixture endpoints closed, including reconciliation.
                        state["barrier_failed"] = True
                        self.send_error(503)
                        return
                self.reply({"ok": True})
            elif self.path == "/api/self/password":
                require(self.headers.get("Authorization") == "Bearer synthetic-token", "password_update_not_authorized")
                salt_bytes = bytes.fromhex(data["salt"].removeprefix(legacy.PREFIX))
                require(data["pass_hash"] == hashlib.pbkdf2_hmac("sha256", b"synthetic-password", salt_bytes, 100000, 32).hex(),
                    "original_login_password_changed")
                state["auth_salt"] = data["salt"]
                state["password_posts"] += 1
                self.reply({"updated": True})
            elif self.path == "/push/batch":
                require(self.headers.get("Authorization") == "Bearer synthetic-token", "transfer_push_not_authorized")
                for item in data["items"]:
                    state["sync_blobs"][item["id"]] = dict(item, user="synthetic")
                self.reply({"replaced": [True] * len(data["items"])})
            else:
                self.send_error(404)

        def do_GET(self):
            if state.get("barrier_failed"):
                self.send_error(503)
                return
            if self.path == "/pull" or self.path.startswith("/pull?"):
                state["sync_pulls"] += 1
                if state["sync_pulls"] == 2:
                    self.reply({"error": "synthetic outage after preflight"}, 503)
                else:
                    blobs = list(state["sync_blobs"].values())
                    self.reply({"blobs": blobs, "cursor": len(blobs), "total": len(blobs),
                                "alive": sum(not item["deleted"] for item in blobs)})
                return
            if self.path == "/auth/salt?user=synthetic":
                self.reply({"salt": state["auth_salt"]})
                return
            if self.path != "/api/self/vault":
                self.send_error(404)
                return
            state["gets"] += 1
            if state["barrier"] == "before_publish" and state["gets"] == 2:
                reached.set()
                if not release.wait(120):
                    state["barrier_failed"] = True
                    self.send_error(503)
                    return
            self.reply(v2 if state.get("stale_vault_read") else state["vault"])

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    addr = f"http://127.0.0.1:{server.server_port}"
    root = args.root / "library"
    root.mkdir(mode=0o700)
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("RSRS_", "ONEMEMORY_", "RESPIRE_", "XDG_"))
           and k not in ("GH_TOKEN", "GITHUB_TOKEN")}
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
    install_published_runtime(args.binary, env)
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
    native_aliases = set()
    try:
        version = cli("--version").stdout.decode()
        require(args.version in version, "binary_version_mismatch")
        initial_session = write_session(v4)
        cli("--direct", "--json", "remember", "Synthetic interruption ciphertext", "--title", "Interruption fixture", "--force", "--importance", "important")
        database = root / "rsrs.db"

        def ciphertexts():
            with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as db:
                return db.execute("SELECT id,ciphertext,nonce FROM memories ORDER BY id").fetchall()

        original_rows = ciphertexts()
        require(len(original_rows) == 1, "ciphertext_fixture_missing")
        cli("--runtime-internal", "--stop")
        # A separate, authentic pre-operation Recovery schema exercises legacy
        # automatic recovery. Never strip operation_id from a live v2 journal.
        recovery_path = root / ".login-recovery.json"
        require(not recovery_path.exists(), "legacy_fixture_requires_clean_journal")
        legacy_alias = "login-" + secrets.token_hex(16)
        native_aliases.add(legacy_alias)
        candidate = dict(json.loads(initial_session), token="synthetic-interrupted-token",
                         keyring_account=legacy_alias)
        legacy_record = {"directory": str(root.resolve()), "original": list(initial_session),
                         "config": list(config_bytes), "alias": legacy_alias,
                         "backends": [], "pass_backends": [], "directory_existed": True}
        if keys:
            for slot, secret in (("super", code), ("pass", "synthetic-password")):
                attributes = keys.attributes("rsrs", slot + ":" + legacy_alias)
                require(not list(keys.collection.search_items(attributes)), "legacy_credential_collision")
                keys.collection.create_item("Synthetic legacy interruption", attributes,
                                            secret.encode(), replace=False)
                legacy_record["backends" if slot == "super" else "pass_backends"] = ["secret_service"]
            candidate["keyring_backend"] = "secret_service"
        session.write_text(json.dumps(candidate))
        config.write_text(json.dumps(dict(json.loads(config_bytes), custom="interrupted")))
        recovery_path.write_text(json.dumps(legacy_record))
        recovery_path.chmod(0o600)
        cli("login", "--interactive", "--addr", addr, "--user", "synthetic",
            "--pass=synthetic-password", "--super=wrong", success=False)
        require(session.read_bytes() == initial_session and config.read_bytes() == config_bytes,
                "legacy_original_profile_not_restored")
        # The rejected new login may leave a terminal receipt, but no recovery owner.
        if recovery_path.exists():
            require(json.loads(recovery_path.read_bytes()).get("active") is None,
                    "legacy_recovery_not_retired")
        if keys:
            for slot in ("super", "pass"):
                require(not list(keys.collection.search_items(keys.attributes("rsrs", slot + ":" + legacy_alias))),
                        "legacy_interrupted_credential_not_deleted")
        require(ciphertexts() == original_rows, "legacy_original_ciphertexts_changed")
        cli("--runtime-internal", "--stop")
        report["cases"]["legacy_pending_automatic_recovery"] = {
            "passed": True, "synthetic_legacy_schema": True, "original_profile_restored": True,
            "ciphertext_preserved": True, "credential_mode": "secret_service" if keys else "headless"}
        for barrier in ("before_publish", "after_publish"):
            state.update(vault=dict(v2), auth_salt=old_auth_salt, gets=0, posts=0,
                         logins=0, password_posts=0, barrier=barrier)
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
            child = subprocess.Popen([str(args.binary), *migration], env=command_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
            require(reached.wait(120), "commit_barrier_not_reached")
            alias = json.loads(session.read_bytes()).get("keyring_account")
            if keys:
                require(re.fullmatch(r"login-[a-f0-9]{32}", alias or "") is not None, "native_alias_missing")
                native_aliases.add(alias)
            require(json.loads(session.read_bytes())["wrapped_urk"].startswith(legacy.PREFIX)
                and json.loads(session.read_bytes())["vault_version"] == 2, "original_vault_factors_changed")
            require((root / ".login-recovery.json").is_file(), "durable_recovery_missing")
            if keys:
                require(json.loads(session.read_bytes()).get("keyring_backend") == "secret_service", "native_backend_not_used")
                attributes = {"service": "rsrs", "username": "super:" + alias}
                items = list(keys.collection.search_items(attributes))
                require(len(items) == 1 and items[0].get_secret().decode() == old_super, "native_credential_not_written")
                password_attributes = {"service": "rsrs", "username": "pass:" + alias}
                passwords = list(keys.collection.search_items(password_attributes))
                require(len(passwords) == 1 and passwords[0].get_secret().decode() == "synthetic-password", "original_password_not_written")
            marker = root / "runtime/autostart/maintenance.json"
            owner = json.loads(marker.read_bytes())["token"]
            journal_bytes = recovery_path.read_bytes()
            record = original_operation(json.loads(journal_bytes), root, barrier, addr)
            require(bytes(json.loads(journal_bytes)["active"]["original"]) == legacy_bytes
                    and bytes(json.loads(journal_bytes)["active"]["config"]) == config_bytes,
                    "original_recovery_image_changed")
            report["cases"][barrier + "_interrupted"] = {
                "phase": record["phase"], "publication_pending": barrier == "after_publish",
                "operation_id": record["operation_id"], "passed": False}
            # The CLI delegates private effects to control children. Interrupt the
            # whole freshly owned session, not just the CLI and leave an orphan POST.
            report["cases"][barrier + "_interrupted"]["process_exit"] = interrupt_owned_control(child)
            child = None
            release.set()
            state["barrier"] = None
            require(state["posts"] == (0 if barrier == "before_publish" else 1), "publication_window_not_proven")
            interrupted_session, interrupted_config = session.read_bytes(), config.read_bytes()
            require(recovery_path.read_bytes() == journal_bytes, "interrupted_operation_advanced")
            effect_counts = state["logins"], state["posts"], state["password_posts"]
            # OperationPending is NOT legacy recovery. A fresh rejected login must
            # preserve the candidate, journal and maintenance owner without replay.
            cli("login", "--interactive", "--addr", addr, "--user", "synthetic", "--pass=synthetic-password", "--super=wrong", success=False)
            require((session.read_bytes(), config.read_bytes(), recovery_path.read_bytes())
                    == (interrupted_session, interrupted_config, journal_bytes), "fresh_login_replaced_original_operation")
            require((state["logins"], state["posts"], state["password_posts"]) == effect_counts,
                    "fresh_login_replayed_authentication")
            require(json.loads(marker.read_bytes())["token"] == owner,
                    "fresh_login_replaced_maintenance_owner")
            if barrier == "before_publish":
                # Querying AwaitingVerification would complete it. Explicit rollback
                # is permitted by the original receipt before any publication starts.
                receipt = json.loads(cli(*account_recovery_flags("account-rollback", record)).stdout)["summary"]
                require(receipt["operation_id"] == record["operation_id"] and receipt["outcome"] == "rolled_back",
                        "original_rollback_not_confirmed")
                terminal_operation(json.loads(recovery_path.read_bytes()), record, "rolled_back")
                require(session.read_bytes() == legacy_bytes and config.read_bytes() == config_bytes,
                        "original_profile_not_restored")
                if keys:
                    require(not list(keys.collection.search_items(attributes)), "interrupted_native_credential_not_deleted")
                    require(not list(keys.collection.search_items(password_attributes)), "interrupted_native_password_not_deleted")
                require((state["logins"], state["posts"], state["password_posts"]) == effect_counts,
                        "rollback_replayed_authentication")
                confirmed = json.loads(cli(*account_recovery_flags("account-result", record)).stdout)["summary"]
                require(confirmed["outcome"] == "rolled_back", "rollback_receipt_not_retained")
                # A fresh migration is safe only after that original terminal rollback.
                cli(*migration)
                require(state["logins"] == effect_counts[0] + 1, "explicit_retry_login_count_changed")
            else:
                # The POST took effect but its response was lost. Compensation must
                # fail and retain keys. Only the original result can reconcile it.
                cli(*account_recovery_flags("account-rollback", record), success=False)
                require((session.read_bytes(), config.read_bytes(), recovery_path.read_bytes())
                        == (interrupted_session, interrupted_config, journal_bytes), "unknown_rollback_changed_material")
                if keys:
                    require(len(list(keys.collection.search_items(attributes))) == 1
                            and len(list(keys.collection.search_items(password_attributes))) == 1,
                            "unknown_rollback_deleted_credentials")
                # An unconfirmed observation is not success or permission to retry.
                # Model a stale server read while retaining the actual POST effect.
                state["stale_vault_read"] = True
                cli(*account_recovery_flags("account-result", record), success=False)
                require((session.read_bytes(), config.read_bytes(), recovery_path.read_bytes())
                        == (interrupted_session, interrupted_config, journal_bytes), "unknown_result_changed_material")
                require(json.loads(marker.read_bytes())["token"] == owner,
                        "unknown_result_released_maintenance")
                require((state["logins"], state["posts"], state["password_posts"]) == effect_counts,
                        "unknown_result_replayed_effect")
                state["stale_vault_read"] = False
                report["cases"][barrier + "_interrupted"]["unknown_retained_maintenance"] = True
                receipt = json.loads(cli(*account_recovery_flags("account-result", record)).stdout)["summary"]
                require(receipt["operation_id"] == record["operation_id"] and receipt["outcome"] == "committed",
                        "original_operation_not_committed")
                terminal_operation(json.loads(recovery_path.read_bytes()), record, "committed")
                require((session.read_bytes(), config.read_bytes()) == (interrupted_session, interrupted_config),
                        "original_candidate_changed_during_completion")
                require(state["logins"] == effect_counts[0], "result_replayed_authentication")
                committed = session.read_bytes(), config.read_bytes(), recovery_path.read_bytes()
                repeated = json.loads(cli(*account_recovery_flags("account-result", record)).stdout)["summary"]
                require(repeated["operation_id"] == record["operation_id"] and repeated["outcome"] == "committed",
                        "original_result_not_repeatable")
                require((session.read_bytes(), config.read_bytes(), recovery_path.read_bytes()) == committed,
                        "repeated_result_changed_material")
            require(state["vault"]["version"] == 2 and state["posts"] == 1
                    and state["password_posts"] == 1, "migration_effects_not_exactly_once")
            vault = state["vault"]
            require(AESGCM(legacy.legacy_kek(2, old_super, "", vault["kdf_salt"], current=True)).decrypt(
                bytes.fromhex(vault["urk_nonce"]), legacy.encrypted_bytes(vault["wrapped_urk"]), None) == urk, "data_key_changed")
            require(ciphertexts() == original_rows, "original_ciphertexts_changed")
            require(json.loads(config.read_bytes()) == json.loads(config_bytes), "API_config_changed")
            cli("--runtime-internal", "--stop")
            report["cases"][barrier + "_interrupted"].update({
                "passed": True, "ciphertext_preserved": True,
                "original_profile_restored": barrier == "before_publish",
                "original_operation_completed": barrier == "after_publish",
                "no_authentication_replay": True, "vault_posts": state["posts"],
                "password_posts": state["password_posts"],
                "credential_mode": "secret_service" if keys else "headless"})
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
            register_witness_functions(backup)
            for memory_id, ciphertext, old_nonce in original_rows:
                plaintext = legacy.decrypt_content(urk, ciphertext, old_nonce)
                old_nonce = secrets.token_bytes(12)
                old_ciphertext = AESGCM(legacy.hkdf(urk, None, b"onememory:data:v1")).encrypt(old_nonce, plaintext, None).hex()
                backup.execute("UPDATE memories SET ciphertext=?,nonce=?,embedding_enc='' WHERE id=?", (old_ciphertext, old_nonce.hex(), memory_id))
                backup.execute("UPDATE core_artifacts SET source=? WHERE memory_id=?", (old_ciphertext, memory_id))
            fixture_witness = verify_fixture_witness(backup)
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
        native_aliases.add(alias)
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
        cli("--runtime-internal", "--stop")
        if fixture_witness is not None:
            chain = json.loads(cli("--direct", "--json", "witness", "--verify").stdout)
            require(chain["status"] == "ok" and chain["summary"]["intact"] is True
                    and chain["summary"]["count"] > fixture_witness["count"], "migrated_fixture_witness_invalid")
            report["fixture_witness"] = {"python_pre_migration": fixture_witness,
                                         "rust_post_migration": chain["summary"]}
        require(state["vault"]["version"] == 2 and ciphertexts() == original_rows, "DEV4_recovery_failed")
        report["cases"]["pre_journal_DEV4_recovery"] = {"passed": True, "wrong_code_rejected": True,
            "inconsistent_factors_rejected": True, "public_original_profile_migration": True,
            "full_library_reencrypted": True, "original_source_preserved": True,
            "original_factors_preserved": True, "requires_original_source": True}
        # Transfer to a different server identity and URK without plaintext exports.
        source_profile = json.loads(cli("--json", "account", "list").stdout)["details"]["accounts"]
        source_name = next(row["name"] for row in source_profile if row["current"])
        source_path = Path(env["RSRS_DATA_DIR"])
        source_session = source_path / "session.json"
        source_value = json.loads(source_session.read_bytes())
        source_value["addr"] = "https://previous.invalid"
        source_value["super"] = old_super  # Synthetic source factor differs from the target env key.
        source_session.write_text(json.dumps(source_value), encoding="utf-8")
        with sqlite3.connect((source_path / "rsrs.db").as_uri() + "?mode=ro", uri=True) as db:
            source_before = source_session.read_bytes(), db.execute("SELECT id,ciphertext,nonce FROM memories ORDER BY id").fetchall()
        cloud_urk = secrets.token_bytes(32)
        cloud_salt, cloud_nonce = secrets.token_hex(16), secrets.token_bytes(12)
        state["vault"] = {"version": 4, "kdf_salt": cloud_salt, "urk_nonce": cloud_nonce.hex(),
            "wrapped_urk": legacy.PREFIX + AESGCM(legacy.v4_kek(code, cloud_salt, legacy.PREFIX)).encrypt(cloud_nonce, cloud_urk, None).hex()}
        state.update(sync_blobs={}, sync_pulls=0)
        transfer = ("--json", "login", "--interactive", "--addr", addr, "--user", "synthetic",
                    "--pass=synthetic-password", "--super", code, "--migrate-local")
        first_result = cli(*transfer, success=False)
        require(first_result.returncode == 2, "server_transfer_sync_warning_missing")
        first = json.loads(first_result.stdout)["summary"]
        require(first["import"]["imported"] == 1 and first["import"]["duplicates"] == 0,
                "server_transfer_count_failed")
        target = Path(first["dir"])
        require(target.resolve() != source_path.resolve(), "server_transfer_reused_source")
        with sqlite3.connect((target / "rsrs.db").as_uri() + "?mode=ro", uri=True) as db:
            copied = db.execute("SELECT ciphertext,nonce FROM memories WHERE deleted=0").fetchall()
        require(len(copied) == 1, "server_transfer_copy_missing")
        copied_payload = json.loads(legacy.decrypt_content(cloud_urk, *copied[0]))
        original_payload = json.loads(legacy.decrypt_content(urk, original_rows[0][1], original_rows[0][2]))
        require(all(copied_payload[field] == original_payload[field] for field in ("content", "title")),
                "server_transfer_not_reencrypted")
        cli("--json", "account", "use", source_name)
        retry_result = cli(*transfer)
        retry = json.loads(retry_result.stdout)["summary"]
        require(retry["import"]["imported"] == 0 and retry["import"]["duplicates"] == 1,
                "server_transfer_retry_duplicated")
        require(len(state["sync_blobs"]) == 1, "server_transfer_remote_duplicated")
        with sqlite3.connect((source_path / "rsrs.db").as_uri() + "?mode=ro", uri=True) as db:
            require((source_session.read_bytes(), db.execute("SELECT id,ciphertext,nonce FROM memories ORDER BY id").fetchall())
                    == source_before, "server_transfer_changed_source")
        report["cases"]["different_server_transfer_retry"] = {"passed": True,
            "source_preserved": True, "different_urk": True, "duplicates_skipped": True}
        report["passed"] = True
    finally:
        if child is not None:
            stop_owned_control(child)
            try:
                stdout, _ = child.communicate(timeout=15)
            except (OSError, subprocess.TimeoutExpired):
                stdout = b""
            report["migration_child"] = {"exit_code": child.returncode,
                "migration_stage": None, "migration_exchange": None, "register_kind": None}
            try:
                value = json.loads(stdout)
            except (ValueError, UnicodeError, RecursionError):
                value = None
            errors = value.get("errors") if isinstance(value, dict) else None
            text = "\n".join(error for error in errors if isinstance(error, str)) if isinstance(errors, list) else ""
            migration_stages = ("paused_grant", "owner_check", "drain_owner", "drained_check",
                "selection_before_send", "save_sent", "exchange", "encode_unknown", "selection_after_receipt",
                "restore_owner_start", "restore_owner_probe", "restore_owner_verify", "restore_store_ready",
                "selection_before_finish", "finish_maintenance", "save_terminal", "paused_publication")
            exchange_categories = ("spawn", "channel", "frame", "encoding", "deadline", "child_exit",
                "response_binding", "response_profile", "response_envelope", "response_readiness", "result_identity",
                "unknown_receipt", "terminal_receipt", "terminal_details", "unclassified", "runtime_invalid_request",
                "runtime_protocol_version_mismatch", "runtime_control_unavailable", "runtime_auth_recovery_pending",
                "runtime_unauthorized", "runtime_auth_ownership_unavailable", "runtime_scope_mismatch",
                "runtime_migration_outcome_unknown", "runtime_control_outcome_unknown")
            register_kinds = ("register_remote_unknown", "register_native_credentials", "register_state_conflict",
                "register_material_invalid", "register_local_compatibility", "register_unclassified")
            for name, allowed in (("migration_stage", migration_stages), ("migration_exchange", exchange_categories),
                                  ("register_kind", register_kinds)):
                token = re.search(r"\b" + name + r"=([a-z_]+)(?=$|[;\s])", text)
                if token and token[1] in allowed and (name != "migration_exchange"
                        or report["migration_child"]["migration_stage"] == "exchange"):
                    report["migration_child"][name] = token[1]
        # Never unblock a request while a surviving private helper can publish it.
        release.set()
        stopped = subprocess.run([str(args.binary), "--runtime-internal", "--stop"], env=env, capture_output=True, timeout=60)
        report["runtime_cleanup"] = {"passed": stopped.returncode in (0, 2)}
        if keys:
            # Discover interrupted aliases only from our synthetic files, including
            # failures before a barrier. Never claim arbitrary credential-store items.
            for path in args.root.rglob("*.json"):
                if path.name not in ("session.json", ".login-recovery.json"):
                    continue
                value = json.loads(path.read_bytes())
                if path.name == ".login-recovery.json" and value.get("schema_version") == 2:
                    for operation in value["operations"]:
                        require(all(Path(operation[key]).resolve().is_relative_to(args.root.resolve())
                                    for key in ("root", "profile")), "credential_journal_outside_fixture")
                        recorded_alias = operation["alias"]
                        require(re.fullmatch(r"login-[a-f0-9]{32}", recorded_alias) is not None,
                                "unowned_fixture_operation_alias")
                        native_aliases.add(recorded_alias)
                alias = value.get("keyring_account") if path.name == "session.json" else (
                    (value.get("active") or {}).get("alias") if "schema_version" in value else value.get("alias"))
                if alias is not None:
                    require(re.fullmatch(r"(?:login-[a-f0-9]{32}|legacy-[a-f0-9]{16})", alias) is not None,
                            "unowned_fixture_alias")
                    native_aliases.add(alias)
            # The authenticated private collection started empty. Require an exact
            # alias from these owned transactions as well as the credential schema.
            for item in keys.collection.get_all_items():
                attributes = item.get_attributes()
                require(attributes.get("service") == "rsrs" and re.fullmatch(r"(?:super|pass):(?:login-[a-f0-9]{32}|legacy-[a-f0-9]{16})", attributes.get("username", "")), "unexpected_private_credential")
                require(attributes["username"].split(":", 1)[1] in native_aliases,
                        "credential_not_bound_to_fixture_transaction")
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
