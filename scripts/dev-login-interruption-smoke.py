#!/usr/bin/env python3
"""Real Linux CLI SIGINT recovery; only synthetic accounts and loopback HTTP."""
from native_fixture_process import install_published_runtime
import argparse
from contextlib import contextmanager
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
import time
import uuid
import select
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

if "--gui-recovery-server" not in sys.argv:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    spec = importlib.util.spec_from_file_location("legacy", Path(__file__).with_name("dev-legacy-vault-smoke.py"))
    legacy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(legacy)
    require = legacy.require




# Only fixed fixture assertions may become diagnostic strings. Never serialize
# arbitrary exception text, subprocess output, paths or account material.
FAILURE_CODES = frozenset(['cli_expectation_failed', 'API_config_changed', 'DEV4_recovery_failed', 'SIGINT_fixture_requires_linux_pidfd', 'binary_hash_mismatch', 'binary_version_mismatch', 'ciphertext_fixture_missing', 'cleanup_control_helper_still_running', 'cleanup_process_identity_changed', 'cleanup_process_lifetime_unproven', 'cleanup_untracked_group_member', 'commit_barrier_not_reached', 'credential_journal_outside_fixture', 'credential_not_bound_to_fixture_transaction', 'data_key_changed', 'durable_recovery_missing', 'explicit_retry_login_count_changed', 'fresh_fixture_required', 'fresh_login_replaced_maintenance_owner', 'fresh_login_replaced_original_operation', 'fresh_login_replayed_authentication', 'full_library_namespace_not_migrated', 'inconsistent_factors_modified_state', 'inconsistent_profile_overwritten', 'interrupted_control_helper_still_running', 'interrupted_group_still_running', 'interrupted_native_credential_not_deleted', 'interrupted_native_password_not_deleted', 'interrupted_operation_advanced', 'interrupted_phase_not_proven', 'interruption_already_completed', 'interruption_child_not_owned', 'interruption_control_helper_not_bound', 'interruption_group_changed', 'interruption_group_has_unbound_member', 'interruption_session_not_owned', 'invalid_publication_barrier', 'invalid_recovery_action', 'failed_login_requires_clean_journal', 'failed_login_interrupted_credential_not_deleted', 'failed_login_original_ciphertexts_changed', 'failed_login_original_profile_not_restored', 'failed_login_recovery_binding_invalid', 'migrated_fixture_witness_invalid', 'migration_effects_not_exactly_once', 'native_alias_missing', 'native_backend_not_used', 'native_credential_not_written', 'native_fixture_cleanup_failed', 'operation_journal_schema_missing', 'operation_recovery_not_retired', 'original_account_identity_changed', 'original_candidate_changed_during_completion', 'original_ciphertexts_changed', 'original_factors_not_recovered', 'original_login_password_changed', 'original_operation_binding_changed', 'original_operation_invalid', 'original_operation_missing', 'original_operation_not_committed', 'original_operation_not_unique', 'original_password_not_written', 'original_plaintext_not_recovered', 'original_profile_not_discovered', 'original_profile_not_migrated', 'original_profile_not_restored', 'original_profile_selection_failed', 'original_recovery_image_changed', 'original_result_not_repeatable', 'original_rollback_not_confirmed', 'original_source_changed', 'original_terminal_receipt_missing', 'original_vault_factors_changed', 'owned_child_not_interrupted', 'owned_runtime_cleanup_failed', 'password_update_not_authorized', 'publication_checkpoint_not_proven', 'publication_window_not_proven', 'repeated_result_changed_material', 'result_replayed_authentication', 'rollback_receipt_not_retained', 'rollback_replayed_authentication', 'server_transfer_changed_source', 'server_transfer_copy_missing', 'server_transfer_count_failed', 'server_transfer_not_reencrypted', 'server_transfer_remote_duplicated', 'server_transfer_retry_duplicated', 'server_transfer_reused_source', 'server_transfer_sync_warning_missing', 'transfer_push_not_authorized', 'unexpected_private_credential', 'unknown_result_changed_material', 'unknown_result_released_maintenance', 'unknown_result_replayed_effect', 'unknown_rollback_changed_material', 'unknown_rollback_deleted_credentials', 'unowned_fixture_alias', 'unowned_fixture_operation_alias', 'wrong_recovery_modified_state'])


FAILURE_CODES = FAILURE_CODES | frozenset({
    "login_continuation_identity_mismatch", "login_continuation_inputs_mismatch",
    "login_continuation_transport_mismatch", "login_continuation_envelope_mismatch",
    "login_continuation_query_failed", "login_continuation_admission_effects_mismatch",
    "login_continuation_maintenance_not_finished",
    "original_operation_binding_changed_idempotency_key", "original_operation_binding_changed_profile",
    "original_operation_binding_changed_root", "original_operation_binding_changed_alias",
    "login_continuation_target_escaped", "unowned_fixture_login_custody",
    "key_continuation_identity_mismatch", "key_continuation_inputs_mismatch",
    "key_continuation_effects_mismatch", "key_continuation_material_changed",
    "key_continuation_unlock_failed", "key_continuation_memory_failed",
    "key_continuation_credential_not_owned", "key_continuation_query_failed",
    "server_transfer_fault_not_observed",
})


@contextmanager
def fixture_report(args, report):
    report["stage"] = "bootstrap"
    try:
        yield
    except BaseException as error:
        report["passed"] = False
        code = str(error) if type(error) is RuntimeError and str(error) in FAILURE_CODES else {
            subprocess.TimeoutExpired: "subprocess_timeout", FileNotFoundError: "required_file_missing",
            PermissionError: "permission_denied", json.JSONDecodeError: "invalid_json",
            KeyboardInterrupt: "interrupted", SystemExit: "early_exit"}.get(type(error), "unclassified_failure")
        report["failure_code"] = code
        raise
    finally:
        # Outermost write also runs when setup or an owned cleanup check raises.
        (args.root / "interruption-coverage.json").write_text(json.dumps(report, indent=2) + "\n")


def safe_cli_diagnostic(stdout, stderr):
    """Keep fixed classifications only; subprocess output can contain account material."""
    try:
        value = json.loads(stdout)
    except (ValueError, UnicodeError, RecursionError):
        value = None
    summary = value.get("summary") if isinstance(value, dict) else None
    reason = summary.get("reason") if isinstance(summary, dict) else None
    reasons = ("account_outcome_unknown", "control_outcome_unknown", "auth_outcome_unknown",
               "request_outcome_unknown", "runtime_error", "invalid_input",
               "account_handoff_pending", "identity_write_recovery_required")
    errors = value.get("errors") if isinstance(value, dict) else None
    text = "\n".join(error for error in errors if isinstance(error, str)) if isinstance(errors, list) else ""
    text += "\n" + stderr.decode("utf-8", errors="replace")
    categories = (
        ("key_source_inline_with_journal", "source factors and an existing login journal require explicit recovery"),
        ("key_source_inline", "this inline source format has no host canonicalization path"),
        ("runtime_unlock_rejected", "Runtime V2 unlock rejected"),
        ("runtime_unlock_transport", "Runtime V2 unlock transport failed"),
        ("runtime_startup_timeout", "host runtime did not become ready"),
        ("runtime_startup_exit", "host runtime exited before readiness"),
        ("runtime_startup_identity", "runtime owner changed during startup"),
        ("config_target_start", "config stage=target_start"),
        ("config_target_owner", "config stage=target_owner_verification"),
        ("config_private_validation", "Runtime did not confirm private config validation"),
        ("config_profile_binding", "candidate selected a different target profile"),
        ("config_source_binding", "config source profile changed since review"),
        ("config_store_not_ready", "configured target Runtime did not confirm store readiness"),
        ("runtime_rpc_transport", "runtime_rpc_transport_failed"),
        ("runtime_account_rejected", "Runtime rejected account control (account_outcome_unknown)"),
        ("control_spawn", "cannot start owned host control Runtime"),
        ("control_response_channel", "host control response channel failure"),
        ("control_deadline", "host control deadline exceeded"),
        ("control_exit_wait", "cannot wait for host control Runtime exit"),
        ("control_exit_mismatch", "host control Runtime exit does not match its response"),
        ("control_response_identity", "account control response identity mismatch"),
        ("control_profile_identity", "account response launch profile mismatch"),
        ("control_parent_or_channel", "parent authorization ended or control channel was interrupted"),
        ("control_parent_or_channel", "auth_diagnostic=auth_parent_revoked_or_channel_interrupted"),
        ("control_authorization", "account launch or parent authorization failed"),
        ("control_binding", "account control binding changed or does not match"),
        ("control_ownership", "account library ownership is unavailable"),
        ("auth_recovery_pending", "authentication recovery requires the original operation"),
        ("host_maintenance_pending", "runtime maintenance is incomplete; use the host runtime restart or the indicated snapshot/login recovery before accessing the library"),
        ("discovery_symlink", "discovery path contains a symlink: "),
        ("discovery_reparse", "discovery path contains a reparse point: "),
        ("discovery_parent_traversal", "discovery path contains parent traversal"),
        ("discovery_ancestor", "discovery ancestor is not a directory"),
        ("discovery_profile_root", "profile root is not a directory"),
        ("migration_control_unknown", "migration_outcome_unknown operation_id="),
        ("login_vault_unlock", "login_kind=vault_unlock_rejected"),
        ("login_account_material", "login_kind=account_material_rejected"),
        ("owned_cleanup", "cleanup_failed owned_pid="),
        ("key_owner_unhealthy", "key control has a recorded owner without verifiable health"),
        ("key_owner_identity", "key owner differs from the installed Runtime, account, profile or registration"),
        ("key_owner_identity", "key owner changed during verification"),
        ("key_selection", "key recovery belongs to another selection"),
        ("key_selection", "key control launch selection changed"),
        ("key_selection", "key operation installation, profile, image or identity changed"),
        ("key_maintenance", "key control requires an actual drained Paused binding"),
        ("key_maintenance", "key control requires owned maintenance"),
        ("key_maintenance", "key control requires this installation's takeover ownership"),
        ("key_maintenance", "key control must own maintenance"),
        ("key_recovery_binding", "invalid key recovery binding"),
        ("key_recovery_binding", "key recovery registration or coordinator changed"),
        ("key_recovery_binding", "key recovery does not own the original maintenance marker"),
        ("key_source_session", "super-reset source session missing"),
        ("key_source_session", "source credential account missing"),
        ("key_source_session", "source credential backend missing"),
        ("key_source_credential", "host session credential read failed"),
        ("key_source_credential", "Runtime session key is unavailable; library remains locked"),
        ("key_credential", "host key credential unavailable"),
        ("key_credential", "host key credential read failed"),
        ("key_credential", "host key credential write failed"),
        ("key_credential", "host key credential readback failed"),
        ("key_credential", "host key credential conflict; original retained"),
        ("key_custody", "host key custody missing; retain the original operation"),
        ("key_custody", "host key candidate credential changed; retain the original operation"),
        ("key_private_exchange", "private key exchange failed; query the original operation"),
        ("key_private_receipt", "invalid private key receipt"),
        ("key_private_receipt", "key receipt changed its original intent or source"),
        ('key_maintenance', 'account and key control must own maintenance independently'),
        ('key_maintenance', 'host maintenance already has an active controller'),
        ('key_maintenance', "maintenance requires this installation's takeover ownership"),
        ('key_maintenance', 'interrupted host maintenance; query the original operation before starting another write'),
        ('key_maintenance', 'maintenance belongs to another coordinator or operation family'),
        ('key_maintenance', 'maintenance still belongs to a live controller'),
        ('key_maintenance', 'maintenance installation or selected profile changed'),
        ('key_maintenance', 'maintenance owner, phase, process birth or exact marker digest changed'),
        ('key_runtime_image', 'Runtime image is not a regular file'),
        ('key_runtime_image', 'Runtime image differs from the selected manifest'),
        ('key_runtime_image', 'Runtime image path changed'),
        ('key_runtime_image', 'account startup requires the registered installed Runtime'),
        ('key_runtime_image', 'account startup cannot select an override instead of the installed Runtime'),
        ('key_source_session', 'RSRS_DATA_DIR must be a nonempty UTF-8 path'),
        ('key_recovery_binding', 'key recovery path is a symlink'),
        ('key_recovery_binding', 'key recovery path is a reparse point'),
        ('key_recovery_binding', 'invalid key recovery file'),
        ('key_recovery_binding', 'invalid key recovery metadata'),
        ('key_recovery_binding', 'key recovery context exceeds its bound'),
        ('key_recovery_binding', 'original key recovery metadata is missing; no new operation was sent'),
        ('key_recovery_binding', 'key operation was not sent; explicit queries cannot admit it'),
        ('key_recovery_binding', 'key source identity changed before admission'),
        ('key_recovery_binding', 'key recovery metadata changed before cleanup'),
        ('key_private_receipt', 'private key receipt missing'),
        ('key_private_receipt', 'invalid key response envelope'),
        ('key_private_receipt', 'invalid private key receipt shape'),
        ('key_private_receipt', 'key receipt does not match the selected session'),
        ('key_private_receipt', 'invalid pending key response'),
        ('key_private_receipt', 'invalid terminal key response'),
        ('key_private_receipt', 'super-reset requires an original bound account'),
        ('key_private_receipt', 'super-reset changed its profile'),
    )
    diagnostic = {"reason": reason if reason in reasons else None,
            "category": next((name for name, marker in categories if marker in text), "unclassified"),
            "stdout_json": isinstance(value, dict), "stderr_present": bool(stderr)}
    # The host migration error deliberately hides its underlying error chain.
    # Preserve only its existing fixed stage, never adjacent operation parameters.
    stages = ("paused_grant", "owner_check", "drain_owner", "drained_check",
        "selection_before_send", "save_sent", "exchange", "encode_unknown", "selection_after_receipt",
        "restore_owner_start", "restore_owner_probe", "restore_owner_verify", "restore_store_ready",
        "selection_before_finish", "finish_maintenance", "save_terminal", "paused_publication")
    stage = re.search(r"\bmigration_stage=([a-z_]+)(?=$|[;\s])", text)
    diagnostic["migration_stage"] = stage[1] if stage and stage[1] in stages else None
    return diagnostic


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
    require(record["idempotency_key"] == operation_id, "original_operation_binding_changed_idempotency_key")
    require(record["profile"] == str(root.resolve()), "original_operation_binding_changed_profile")
    require(record["root"] == str(root.resolve()), "original_operation_binding_changed_root")
    require(active["alias"] == record["alias"], "original_operation_binding_changed_alias")
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


def login_terminal_operation(journal, record, summary, session_bytes):
    # Host custody replaces the admission alias with the committed candidate alias.
    session = json.loads(session_bytes)
    alias = session.get("keyring_account")
    sha256 = hashlib.sha256(session_bytes).hexdigest()
    rows = [row for row in journal["operations"] if row["operation_id"] == record["operation_id"]]
    require(isinstance(alias, str) and re.fullmatch(r"login-[a-f0-9]{32}", alias)
            and summary.get("session_sha256") == sha256 and len(rows) == 1
            and rows[0].get("candidate_sha256") == sha256
            and rows[0]["account"].get("target") == summary["target_profile"]
            and all(session.get(key) == record["account"][key] == rows[0]["account"][key]
                    for key in ("user", "addr")), "original_terminal_receipt_missing")
    terminal_operation(journal, dict(record, alias=alias), "committed")


def login_continuation_receipt(summary, operation_id, source, addr, outcome):
    require(summary.get("operation_id") == operation_id
            and summary.get("source_profile") == str(source.resolve())
            and summary.get("outcome") == outcome, "login_continuation_identity_mismatch")
    login = summary.get("login") or {}
    require(login.get("user") == "synthetic" and login.get("addr") == addr
            and login.get("required_inputs") == (["super_password"] if outcome == "awaiting_input" else []),
            "login_continuation_inputs_mismatch")


def runtime_stop_receipt(stopped):
    require(stopped.returncode == 0, "owned_runtime_cleanup_failed")
    receipt = json.loads(stopped.stdout)
    require(receipt.get("status") == "ok" and not receipt.get("errors")
            and receipt.get("summary", {}).get("state") == "stopped", "owned_runtime_cleanup_failed")


def fixture_runtime_owners(directory, images):
    """Match owned images before reading private profile scope from argv/environment."""
    images = {Path(image).resolve() for image in images}
    owners = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            if entry.stat().st_uid != os.geteuid():
                continue
            argv = (entry / "cmdline").read_bytes().split(b"\0")
            # Spawned CLI/Runtime argv[0] is its executable path; inspect only those images.
            if not argv[0] or Path(os.fsdecode(argv[0])).resolve() not in images:
                continue
            if (entry / "exe").resolve(strict=True) not in images:
                continue
            profiles = [argv[index + 1] for index, arg in enumerate(argv[:-1]) if arg == b"--data-dir"]
            profiles.extend(arg.split(b"=", 1)[1] for arg in argv if arg.startswith(b"--data-dir="))
            environment = (entry / "environ").read_bytes().split(b"\0")
            profiles.extend(item.split(b"=", 1)[1] for item in environment
                            if item.startswith(b"RSRS_DATA_DIR="))
            if not any(Path(os.fsdecode(profile)).resolve().is_relative_to(directory.resolve())
                       for profile in profiles):
                continue
            raw = (entry / "stat").read_text()
            if raw[raw.rfind(")") + 2:].split()[0] != "Z":
                owners.append(int(entry.name))
        except (FileNotFoundError, ProcessLookupError):
            continue
    return owners


def key_continuation_receipt(summary, operation_id, source, outcome):
    require(summary.get("operation_id") == operation_id
            and summary.get("source_profile") == str(source.resolve())
            and summary.get("outcome") == outcome, "key_continuation_identity_mismatch")
    if outcome == "awaiting_input":
        require(summary.get("operation", {}).get("kind") == "super_reset"
                and summary.get("required_inputs") == ["super_password"]
                and not summary.get("super_password") and not summary.get("super"),
                "key_continuation_inputs_mismatch")
    else:
        require(summary.get("ok") is True and isinstance(summary.get("super"), str)
                and bool(summary["super"]), "key_continuation_inputs_mismatch")


def remove_fixture_super(keys, session_path, directory, addr, code):
    """Delete only the exact super slot bound to this synthetic V4 login."""
    require(session_path.resolve().is_relative_to(directory.resolve()), "key_continuation_credential_not_owned")
    session = json.loads(session_path.read_bytes())
    alias = session.get("keyring_account")
    require(session.get("user") == "synthetic" and session.get("addr") == addr
            and session.get("vault_version") == 4 and session.get("keyring_backend") == "secret_service"
            and isinstance(alias, str) and re.fullmatch(r"login-[a-f0-9]{32}", alias)
            and all(field not in session for field in ("super", "pass", "secret", "secret_key")),
            "key_continuation_credential_not_owned")
    keys.verify_owner()
    items = [keys._find("rsrs", prefix + alias) for prefix in ("super:", "pass:")]
    for item, prefix in zip(items, ("super:", "pass:")):
        require(item is not None and all(item.get_attributes().get(key) == value
                for key, value in keys.attributes("rsrs", prefix + alias).items()),
                "key_continuation_credential_not_owned")
    require(items[0].get_secret().decode("utf-8") == code, "key_continuation_credential_not_owned")
    password = items[1].get_secret()
    items[0].delete()
    require(keys._find("rsrs", "super:" + alias) is None
            and keys._find("rsrs", "pass:" + alias).get_secret() == password,
            "key_continuation_credential_not_owned")


def host_key_continuation(binary, directory, env, state, addr, code, keys, source, rpc, observation):
    """Reach Runtime's missing-super branch without modifying its operation journal."""
    observation.update(passed=False, stage="remove_source_super")
    session_path = source / "session.json"
    original_session = session_path.read_bytes()
    vault = json.loads(original_session)
    original_urk = AESGCM(legacy.v4_kek(code, vault["kdf_salt"], vault["wrapped_urk"])).decrypt(
        bytes.fromhex(vault["urk_nonce"]), legacy.encrypted_bytes(vault["wrapped_urk"]), None)
    remove_fixture_super(keys, session_path, directory, addr, code)
    effects = state["logins"], state["posts"], state["password_posts"]
    observation["stage"] = "reset_without_super"
    pending, initial_transport = rpc("auth.reset", {}, 2)
    operation_id = pending.get("operation_id")
    require(isinstance(operation_id, str) and str(uuid.UUID(operation_id)) == operation_id
            and uuid.UUID(operation_id).version == 4 and operation_id != initial_transport,
            "key_continuation_identity_mismatch")
    key_continuation_receipt(pending, operation_id, source, "awaiting_input")
    require(session_path.read_bytes() == original_session
            and (state["logins"], state["posts"], state["password_posts"]) == effects,
            "key_continuation_effects_mismatch")
    journal_path = Path(env["RSRS_DATA_DIR"]) / ".login-recovery.json"
    pending_journal = journal_path.read_bytes()

    def query(expected_exit, outcome):
        result = subprocess.run([str(binary), "--json", "runtime", "key-result", "--operation-id", operation_id,
            "--source-profile", str(source.resolve())], env=env, capture_output=True, timeout=180)
        envelope = json.loads(result.stdout)
        require(result.returncode == expected_exit and envelope.get("status") == ("pending" if expected_exit == 2 else "ok")
                and not envelope.get("errors"), "key_continuation_query_failed")
        summary = envelope.get("summary") or {}
        key_continuation_receipt(summary, operation_id, source, outcome)
        return summary

    observation.update(operation_id=operation_id, stage="query_original_pending")
    query(2, "awaiting_input")
    require(session_path.read_bytes() == original_session and journal_path.read_bytes() == pending_journal
            and (state["logins"], state["posts"], state["password_posts"]) == effects,
            "key_continuation_effects_mismatch")
    observation["stage"] = "continue_original_key"
    params = {"operation_id": operation_id, "source_profile": str(source.resolve()),
              "input": {"super_password": code}}
    committed, continue_transport = rpc("auth.key.continue", params, 0)
    key_continuation_receipt(committed, operation_id, source, "committed")
    require(continue_transport not in (initial_transport, operation_id), "login_continuation_transport_mismatch")
    require((state["logins"], state["posts"], state["password_posts"])
            == (effects[0], effects[1] + 1, effects[2]), "key_continuation_effects_mismatch")
    effects = state["logins"], state["posts"], state["password_posts"]
    saved = session_path.read_bytes(), journal_path.read_bytes(), dict(state["vault"])
    observation["stage"] = "recover_committed_key"
    require(query(0, "committed")["super"] == committed["super"], "key_continuation_material_changed")
    repeated, repeated_transport = rpc("auth.key.continue", params, 0)
    key_continuation_receipt(repeated, operation_id, source, "committed")
    require(repeated_transport not in (initial_transport, continue_transport, operation_id),
            "login_continuation_transport_mismatch")
    require(repeated["super"] == committed["super"]
            and (session_path.read_bytes(), journal_path.read_bytes(), state["vault"]) == saved
            and (state["logins"], state["posts"], state["password_posts"]) == effects,
            "key_continuation_material_changed")
    vault = json.loads(session_path.read_bytes())
    published = {"version": vault["vault_version"], **{key: vault[key]
                 for key in ("kdf_salt", "wrapped_urk", "urk_nonce")}}
    require(published == state["vault"] and committed["super"] != code, "key_continuation_material_changed")
    new_urk = AESGCM(legacy.v4_kek(committed["super"], vault["kdf_salt"], vault["wrapped_urk"])).decrypt(
        bytes.fromhex(vault["urk_nonce"]), legacy.encrypted_bytes(vault["wrapped_urk"]), None)
    require(new_urk == original_urk, "key_continuation_unlock_failed")
    observation["stage"] = "post_reset_memory"
    plaintext, title = "Synthetic memory after key continuation", "Key continuation fixture"
    written = subprocess.run([str(binary), "--json", "remember", plaintext, "--title", title,
        "--force", "--importance", "important"], env=env, capture_output=True, timeout=180)
    require(written.returncode == 0, "key_continuation_memory_failed")
    with sqlite3.connect((source / "rsrs.db").as_uri() + "?mode=ro", uri=True) as db:
        rows = db.execute("SELECT id,ciphertext,nonce FROM memories WHERE title=? AND deleted=0", (title,)).fetchall()
    require(len(rows) == 1 and plaintext.encode() in legacy.decrypt_content(new_urk, rows[0][1], rows[0][2]),
            "key_continuation_memory_failed")
    shown = subprocess.run([str(binary), "--json", "show", rows[0][0]], env=env,
        capture_output=True, timeout=180)
    require(shown.returncode == 0 and plaintext in json.dumps(json.loads(shown.stdout)),
            "key_continuation_memory_failed")
    # Recall can observe the persisted source before its derived index is ready.
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        recalled = subprocess.run([str(binary), "--json", "recall", plaintext, "--titles"], env=env,
            capture_output=True, timeout=180)
        envelope = json.loads(recalled.stdout)
        require(recalled.returncode == 0 and envelope.get("status") == "ok" and not envelope.get("errors"),
                "key_continuation_memory_failed")
        if any(row.get("id") == rows[0][0] and row.get("title") == title for row in envelope["details"]):
            break
        time.sleep(.1)
    else:
        raise RuntimeError("key_continuation_memory_failed")
    observation.update(passed=True, stage="committed", awaiting_input_observed=True,
        source_super_only_deleted=True, original_operation_committed=True, distinct_transport_ids=True,
        reset_published_once=True, recovery_without_reset_replay=True, repeated_material_unchanged=True,
        new_super_decrypts_original_urk=True, post_reset_remember_recall=True)


def host_login_continuation(binary, directory, env, state, addr, code, observation, keys, key_observation):
    """Real host admission without a super key; only the original operation may resume."""
    directory.mkdir(mode=0o700)
    source, home = directory / "library", directory / "home"
    source.mkdir(mode=0o700)
    home.mkdir(mode=0o700)
    command_env = dict(env, HOME=str(home), RSRS_DATA_DIR=str(source))
    command_env.pop("RSRS_SUPER", None)
    command_env.pop("RSRS_RUNTIME_BIN", None)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        command_env["RSRS_RPC_PORT"] = str(listener.getsockname()[1])
    observation.update(passed=False, stage="runtime_install")
    installed_runtime = install_published_runtime(binary, command_env)
    images = [binary]
    if installed_runtime is not None:
        images.append(installed_runtime)
    if command_env.get("RSRS_BIN_DIR"):
        images.append(Path(command_env["RSRS_BIN_DIR"]) / "rsrs")

    def rpc(method, params, expected_exit):
        transport_id = "host-login-" + uuid.uuid4().hex
        request = {"v": 1, "id": transport_id, "method": method, "params": params}
        result = subprocess.run([str(binary), "--json", "--host-rpc-stdio"],
            input=json.dumps(request).encode(), env=command_env, capture_output=True, timeout=180)
        reply = json.loads(result.stdout)
        envelope = reply.get("envelope") or {}
        status, outcome = envelope.get("status"), (envelope.get("summary") or {}).get("outcome")
        observation["last_rpc"] = {"method": method, "exit": result.returncode,
            "status": status if status in ("pending", "ok", "warn", "fail") else "unrecognized",
            "outcome": outcome if outcome in ("awaiting_input", "awaiting_verification", "committed",
                "rolled_back", "pending", "unknown") else "absent-or-unrecognized"}
        if result.returncode != expected_exit:
            observation["last_rpc"]["diagnostic"] = safe_cli_diagnostic(json.dumps(envelope).encode(), result.stderr)
        require(result.returncode == expected_exit and reply.get("v") == 1
                and reply.get("id") == transport_id and reply.get("exit") == expected_exit
                and reply.get("ok") is (expected_exit == 0), "login_continuation_transport_mismatch")
        require(envelope.get("status") == ("pending" if expected_exit == 2 else "ok")
                and not envelope.get("errors"), "login_continuation_envelope_mismatch")
        return envelope["summary"], transport_id

    def query(expected_exit):
        result = subprocess.run([str(binary), *account_recovery_flags("account-result", record)],
            env=command_env, capture_output=True, timeout=180)
        require(result.returncode == expected_exit, "login_continuation_query_failed")
        envelope = json.loads(result.stdout)
        require(envelope.get("status") == ("pending" if expected_exit == 2 else "ok")
                and not envelope.get("errors"), "login_continuation_envelope_mismatch")
        return envelope["summary"]

    effects = state["logins"], state["posts"], state["password_posts"]
    try:
        observation["stage"] = "admit_without_super"
        pending, initial_transport = rpc("auth.login",
            {"addr": addr, "user": "synthetic", "password": "synthetic-password"}, 2)
        operation_id = pending.get("operation_id")
        require(isinstance(operation_id, str), "original_operation_missing")
        parsed = uuid.UUID(operation_id)
        require(parsed.version == 4 and str(parsed) == operation_id
                and operation_id != initial_transport, "original_operation_invalid")
        login_continuation_receipt(pending, operation_id, source, addr, "awaiting_input")
        journal_path = source / ".login-recovery.json"
        journal = json.loads(journal_path.read_bytes())
        rows = [row for row in journal["operations"] if row["operation_id"] == operation_id]
        require(len(rows) == 1 and rows[0]["idempotency_key"] == operation_id
                and rows[0]["root"] == str(source.resolve()) and rows[0]["profile"] == str(source.resolve())
                and journal["active"]["operation_id"] == operation_id, "original_operation_binding_changed")
        record = rows[0]
        require((state["logins"], state["posts"], state["password_posts"])
                == (effects[0] + 1, effects[1], effects[2]), "login_continuation_admission_effects_mismatch")
        effects = state["logins"], state["posts"], state["password_posts"]
        observation.update(operation_id=operation_id, stage="query_original_pending")
        login_continuation_receipt(query(2), operation_id, source, addr, "awaiting_input")
        require((state["logins"], state["posts"], state["password_posts"]) == effects,
                "result_replayed_authentication")
        observation["stage"] = "continue_original"
        params = {"operation_id": operation_id, "source_profile": str(source.resolve()),
                  "continuation": {}, "super_password": code}
        committed, continue_transport = rpc("auth.login.continue", params, 0)
        require(continue_transport != initial_transport and continue_transport != operation_id,
                "login_continuation_transport_mismatch")
        login_continuation_receipt(committed, operation_id, source, addr, "committed")
        target = Path(committed["target_profile"])
        require(target.resolve().is_relative_to(source.resolve()), "login_continuation_target_escaped")
        session_path = target / "session.json"
        login_terminal_operation(json.loads(journal_path.read_bytes()), record, committed, session_path.read_bytes())
        saved = session_path.read_bytes(), journal_path.read_bytes()
        observation["stage"] = "recover_committed_original"
        login_continuation_receipt(query(0), operation_id, source, addr, "committed")
        repeated, repeated_transport = rpc("auth.login.continue", params, 0)
        require(repeated_transport not in (initial_transport, continue_transport, operation_id),
                "login_continuation_transport_mismatch")
        login_continuation_receipt(repeated, operation_id, source, addr, "committed")
        require(not (source / "runtime/autostart/maintenance.json").exists(),
                "login_continuation_maintenance_not_finished")
        require((session_path.read_bytes(), journal_path.read_bytes()) == saved,
                "repeated_result_changed_material")
        require((state["logins"], state["posts"], state["password_posts"]) == effects,
                "result_replayed_authentication")
        observation.update(stage="committed", awaiting_input_observed=True, original_operation_committed=True,
            recovery_without_authentication_replay=True, distinct_transport_ids=True, repeated_material_unchanged=True)
        host_key_continuation(binary, directory, command_env, state, addr, code, keys, target, rpc, key_observation)
    finally:
        observation["runtime_cleanup"] = {"passed": False}
        stopped = subprocess.run([str(binary), "--json", "--runtime-internal", "--stop"],
            env=command_env, capture_output=True, timeout=60)
        runtime_stop_receipt(stopped)
        require(not fixture_runtime_owners(directory, images), "owned_runtime_cleanup_failed")
        observation["runtime_cleanup"].update(passed=True, stopped_confirmed=True, no_live_owner=True)
        key_observation["runtime_cleanup"] = dict(observation["runtime_cleanup"])
    observation["passed"] = True


def account_fixture_handler(state, reached, release, v2=None):
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
            if self.path == "/register" and "receipt" in state:
                if state["registers"] != 0 or data.get("user") != "synthetic" or not data.get("pass_hash") or not data.get("salt"):
                    self.send_error(409)
                    return
                state["registers"] += 1
                state["auth_salt"] = data["salt"]
                Path(state["receipt"]).write_text(json.dumps({key: state[key] for key in ("posts", "registers", "logins")}), encoding="utf-8")
                self.reply({"user": "synthetic", "token": state["token"]})
            elif self.path == "/login":
                state["logins"] += 1
                if "receipt" in state:
                    Path(state["receipt"]).write_text(json.dumps({key: state[key] for key in ("posts", "registers", "logins")}), encoding="utf-8")
                    self.reply({"user": "synthetic", "token": state["token"], "session_id": "fixture"})
                    return
                self.reply({"user": "synthetic", "token": "synthetic-token", "session_id": "fixture"})
            elif self.path == "/api/self/vault":
                if self.headers.get("Authorization") != "Bearer " + state.get("token", "synthetic-token"):
                    self.send_error(401)
                    return
                state["vault"] = data
                state["posts"] += 1
                if "receipt" in state:
                    Path(state["receipt"]).write_text(json.dumps({key: state[key] for key in ("posts", "registers", "logins")}), encoding="utf-8")
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
                stage = state["transfer_stage"]
                rejected = stage == "initial_login"
                state["transfer_http"].append({"stage": stage, "method": "POST",
                    "route": "/push/batch", "status": 503 if rejected else 200})
                if rejected:
                    self.reply({"error": "synthetic transfer push outage"}, 503)
                    return
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
                state["transfer_http"].append({"stage": state["transfer_stage"],
                    "method": "GET", "route": "/pull", "status": 200})
                blobs = list(state["sync_blobs"].values())
                self.reply({"blobs": blobs, "cursor": len(blobs), "total": len(blobs),
                            "alive": sum(not item["deleted"] for item in blobs)})
                return
            if self.path == "/auth/salt?user=synthetic":
                if state.get("auth_salt") is None:
                    self.send_error(404)
                    return
                self.reply({"salt": state["auth_salt"]})
                return
            if self.path != "/api/self/vault":
                self.send_error(404)
                return
            if self.headers.get("Authorization") != "Bearer " + state.get("token", "synthetic-token"):
                self.send_error(401)
                return
            state["gets"] += 1
            if state["vault"] is None:
                self.send_error(404)
                return
            # Runtime23 prepares migration twice around host credential custody;
            # only the third vault GET checks publication after candidate commit.
            if state["barrier"] == "before_publish" and state["gets"] == 3:
                reached.set()
                if not release.wait(120):
                    state["barrier_failed"] = True
                    self.send_error(503)
                    return
            self.reply(v2 if state.get("stale_vault_read") else state["vault"])

    return Handler


def gui_recovery_server():
    """Reuse the loopback account service for CLI fixture setup and real GUI reset.

    Only encrypted vault uploads are stored in memory. CLI/Runtime issue all
    recovery material; this server never supplies a super or operation receipt.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("--gui-recovery-server", action="store_true")
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
        raise RuntimeError("hosted_account_fixture_required")
    state = {"vault": None, "posts": 0, "gets": 0, "registers": 0, "logins": 0,
             "barrier": None, "receipt": str(args.receipt), "token": secrets.token_urlsafe(32)}
    server = ThreadingHTTPServer(("127.0.0.1", 0), account_fixture_handler(state, None, None))
    args.receipt.write_text(json.dumps({key: state[key] for key in ("posts", "registers", "logins")}), encoding="utf-8")
    print(json.dumps({"addr": f"http://127.0.0.1:{server.server_port}"}), flush=True)
    server.serve_forever()


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
              "binary_sha256": args.binary_sha256, "passed": False, "cases": {},
              "credential_mode": "secret_service" if args.native_credentials else "headless"}
    with fixture_report(args, report):
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

        Handler = account_fixture_handler(state, reached, release, v2)
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
        report["stage"] = "runtime_install"
        install_published_runtime(args.binary, env)
        report["stage"] = "profile_setup"
        session = root / "session.json"
        config = root / "client.json"
        config_bytes = json.dumps({"data_dir": str(root), "api_base": "https://previous.invalid", "custom": "preserve"}).encode()
        config.write_bytes(config_bytes)

        def write_session(vault):
            value = {"user": "synthetic", "addr": addr, "token": "synthetic-token", "vault_version": vault["version"],
                     **{k: v for k, v in vault.items() if k != "version"}}
            if vault["wrapped_urk"].startswith(legacy.PREFIX):
                value["crypto_namespace"] = legacy.PREFIX
            if keys:
                alias = "legacy-" + secrets.token_hex(8)
                keys.put("rsrs", "super:" + alias, code if vault["version"] == 4 else old_super)
                keys.put("rsrs", "pass:" + alias, "synthetic-password")
                value.update(keyring_account=alias, keyring_backend=keys.credential_backend)
                native_aliases.add(alias)
            session.write_text(json.dumps(value))
            session.chmod(0o600)
            return session.read_bytes()

        def cli(*flags, success=True):
            command_env = dict(env)
            # A profile switch must unlock with that session's native credential,
            # never the unrelated initial v4 fixture's global super override.
            if keys:
                command_env.pop("RSRS_SUPER", None)
            elif "migrate" in flags:
                command_env["RSRS_SUPER"] = old_super
            result = subprocess.run([str(args.binary), *flags], env=command_env, capture_output=True, timeout=180)
            if (result.returncode == 0) != success:
                command = next((name for name in ("account-rollback", "account-result", "login", "remember",
                    "migrate", "--runtime-internal", "--version") if name in flags), "other")
                report["failure"] = {"exit_code": result.returncode, "code": "cli_expectation_failed",
                                     "command": command,
                                     "diagnostic": safe_cli_diagnostic(result.stdout, result.stderr)}
                raise RuntimeError("cli_expectation_failed")
            return result

        migration = ["--direct", "--json", "migrate", "--vault", "--addr", addr, "--user", "synthetic",
                     "--pass=synthetic-password", "--super", old_super, "--new-super", old_super]
        child = None
        migration_keys = None
        native_aliases = set()
        try:
            report["stage"] = "host_login_continue"
            report["cases"]["host_login_continue"] = {"status": "not-evaluated-private-secret-service-required"}
            report["cases"]["host_key_continue"] = {"status": "not-evaluated-private-secret-service-required"}
            if keys:
                report["cases"]["host_login_continue"] = {}
                report["cases"]["host_key_continue"] = {}
                host_login_continuation(args.binary, args.root / "host-login-continue", env, state, addr, code,
                                        report["cases"]["host_login_continue"], keys, report["cases"]["host_key_continue"])
                state["vault"] = v4
            report["stage"] = "initial_authentication"
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
            # Check rollback from the current host state; historical compatibility is database-only.
            initial_session, config_bytes = session.read_bytes(), config.read_bytes()
            recovery_path = root / ".login-recovery.json"
            require(not recovery_path.exists(), "failed_login_requires_clean_journal")
            rejected = json.loads(cli("--json", "login", "--interactive", "--addr", addr, "--user", "synthetic",
                "--pass=synthetic-password", "--super=wrong", success=False).stdout)
            require(session.read_bytes() == initial_session and config.read_bytes() == config_bytes,
                    "failed_login_original_profile_not_restored")
            # Resolve only this failed login's original operation; do not replay authentication.
            report["failed_login_diagnostic"] = safe_cli_diagnostic(json.dumps(rejected).encode(), b"")
            require(recovery_path.is_file(), "failed_login_recovery_binding_invalid")
            journal = json.loads(recovery_path.read_bytes())
            active = journal.get("active") or {}
            operation_id = rejected.get("details", {}).get("operation_id")
            require(rejected.get("summary", {}).get("reason") == "account_outcome_unknown"
                    and any(error.endswith("; login_kind=vault_unlock_rejected") for error in rejected.get("errors", []))
                    and active.get("operation_id") == operation_id
                    and re.fullmatch(r"login-[a-f0-9]{32}", active.get("alias") or ""),
                    "failed_login_recovery_binding_invalid")
            rejected_alias = active["alias"]
            native_aliases.add(rejected_alias)
            records = [row for row in journal["operations"] if row["operation_id"] == operation_id]
            require(len(records) == 1 and records[0]["profile"] == str(root.resolve())
                    and records[0]["account"]["user"] == "synthetic" and records[0]["account"]["addr"] == addr,
                    "original_operation_binding_changed")
            rejected_record = records[0]
            logins_before = state["logins"]
            rollback = cli(*account_recovery_flags("account-rollback", rejected_record), success=False)
            rolled_back = json.loads(rollback.stdout)
            receipt = rolled_back["summary"]
            require(rollback.returncode == 1 and rolled_back.get("status") == "fail"
                    and receipt["operation_id"] == operation_id
                    and receipt["outcome"] == "rolled_back"
                    and state["logins"] == logins_before, "original_rollback_not_confirmed")
            journal = json.loads(recovery_path.read_bytes())
            require(len(journal["operations"]) == 1, "original_operation_not_unique")
            terminal_operation(journal, rejected_record, "rolled_back")
            require(session.read_bytes() == initial_session and config.read_bytes() == config_bytes,
                    "failed_login_original_profile_not_restored")
            if keys:
                for slot in ("super", "pass"):
                    require(not list(keys.collection.search_items(keys.attributes("rsrs", slot + ":" + rejected_alias))),
                            "failed_login_interrupted_credential_not_deleted")
            require(ciphertexts() == original_rows, "failed_login_original_ciphertexts_changed")
            cli("--runtime-internal", "--stop")
            report["cases"]["failed_login_explicit_rollback"] = {
                "passed": True, "current_journal_schema": True, "original_profile_restored": True,
                "ciphertext_preserved": True, "credential_mode": "secret_service" if keys else "headless"}
            # Recovery must unlock the legacy candidate, not the initial v4 fixture.
            env["RSRS_SUPER"] = old_super
            for barrier in ("before_publish", "after_publish"):
                report["stage"] = barrier
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
                # Native credential names belong to the host custody record, not Runtime's recovery alias.
                active = json.loads(recovery_path.read_bytes())["active"]
                custody = json.loads((root / "runtime/autostart" / ("account-login-" + active["operation_id"] + ".json")).read_bytes())
                alias = custody["account"]
                require(custody["operation_id"] == active["operation_id"]
                        and alias == "login-" + uuid.UUID(active["operation_id"]).hex
                        and Path(custody["root"]).resolve() == root.resolve()
                        and Path(custody["source"]).resolve() == root.resolve(),
                        "unowned_fixture_login_custody")
                if keys:
                    require(custody["backend"] == "secret_service", "native_backend_not_used")
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
                    rollback = cli(*account_recovery_flags("account-rollback", record), success=False)
                    rolled_back = json.loads(rollback.stdout)
                    receipt = rolled_back["summary"]
                    require(rollback.returncode == 1 and rolled_back.get("status") == "fail"
                            and receipt["operation_id"] == record["operation_id"]
                            and receipt["outcome"] == "rolled_back",
                            "original_rollback_not_confirmed")
                    terminal_operation(json.loads(recovery_path.read_bytes()), record, "rolled_back")
                    require(session.read_bytes() == legacy_bytes and config.read_bytes() == config_bytes,
                            "original_profile_not_restored")
                    if keys:
                        require(not list(keys.collection.search_items(attributes)), "interrupted_native_credential_not_deleted")
                        require(not list(keys.collection.search_items(password_attributes)), "interrupted_native_password_not_deleted")
                    require((state["logins"], state["posts"], state["password_posts"]) == effect_counts,
                            "rollback_replayed_authentication")
                    queried = cli(*account_recovery_flags("account-result", record), success=False)
                    confirmed = json.loads(queried.stdout)
                    require(queried.returncode == 1 and confirmed.get("status") == "fail"
                            and confirmed["summary"]["outcome"] == "rolled_back",
                            "rollback_receipt_not_retained")
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
            env["RSRS_SUPER"] = code
            report["stage"] = "legacy_recovery"
            # DEV.4 has no journal. Preserve its inconsistent profile and recover by
            # importing the actual original library through the public migration API.
            state.update(vault=dict(v2), gets=0, posts=0, barrier=None)
            write_session(v4)
            before = session.read_bytes()
            wrong = list(migration)
            wrong[-1] = "A3-000000-000000-000000-000000-000000-000000"
            def reject_legacy_migration(flags):
                previous_ids = {row["operation_id"] for row in json.loads(recovery_path.read_bytes())["operations"]}
                rejected = json.loads(cli(*flags, success=False).stdout)
                operation_id = rejected.get("details", {}).get("operation_id")
                require(isinstance(operation_id, str) and str(uuid.UUID(operation_id)) == operation_id
                        and uuid.UUID(operation_id).version == 4 and operation_id not in previous_ids
                        and rejected.get("summary", {}).get("reason") == "account_outcome_unknown"
                        and rejected["details"].get("source_profile") == str(root.resolve()),
                        "original_operation_binding_changed")
                journal = json.loads(recovery_path.read_bytes())
                rows = [row for row in journal["operations"] if row["operation_id"] == operation_id]
                require(journal.get("schema_version") == 2 and len(rows) == 1,
                        "original_operation_not_unique")
                record = rows[0]
                active = journal.get("active") or {}
                account = record.get("account") or {}
                login = account.get("login") or {}
                require(record["idempotency_key"] == operation_id and record["root"] == str(root.resolve())
                        and record["profile"] == str(root.resolve()) and active.get("operation_id") == operation_id
                        and active.get("alias") == record["alias"]
                        and re.fullmatch(r"login-[a-f0-9]{32}", record["alias"]) is not None
                        and account.get("register") is False and account.get("user") == "synthetic"
                        and account.get("addr") == addr and login.get("migrate_vault") is True
                        and all(login.get(key) is False for key in
                            ("publication_pending", "publication_done", "vault_done", "password_done")),
                        "original_operation_binding_changed")
                native_aliases.add(record["alias"])
                effects = state["logins"], state["posts"], state["password_posts"]
                # Each negative case retains its own operation; retire it through the public rollback API.
                rolled_back = json.loads(cli(*account_recovery_flags("account-rollback", record), success=False).stdout)
                require(rolled_back.get("status") == "fail" and rolled_back["summary"]["operation_id"] == operation_id
                        and rolled_back["summary"]["outcome"] == "rolled_back",
                        "original_rollback_not_confirmed")
                terminal_operation(json.loads(recovery_path.read_bytes()), record, "rolled_back")
                require((state["logins"], state["posts"], state["password_posts"]) == effects,
                        "rollback_replayed_authentication")

            report["stage"] = "legacy_recovery_reject_wrong_super"
            reject_legacy_migration(wrong)
            require(session.read_bytes() == before and state["posts"] == 0, "wrong_recovery_modified_state")
            report["stage"] = "legacy_recovery_reject_inconsistent_material"
            reject_legacy_migration(migration)
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
            report["stage"] = "legacy_recovery_discover_profiles"
            discovered = json.loads(cli("--json", "migrate").stdout)["details"]["profiles"]
            candidates = [row for row in discovered if Path(row["source"]).resolve() == source.resolve()]
            require(len(candidates) == 1, "original_profile_not_discovered")
            report["stage"] = "legacy_recovery_import_profile"
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
            require(AESGCM(legacy.legacy_kek(2, old_super, "", restored_session["kdf_salt"], current=True)).decrypt(
                bytes.fromhex(restored_session["urk_nonce"]), legacy.encrypted_bytes(restored_session["wrapped_urk"]), None) == urk,
                "data_key_changed")
            report["stage"] = "legacy_recovery_select_profile"
            report["profile_selection_probe"] = {
                "installation_matches_fixture": Path(env["RSRS_DATA_DIR"]).resolve() == root.resolve(),
                "runtime_inside_installation": Path(env["RSRS_RUNTIME_BIN"]).resolve().is_relative_to(root.resolve()),
                "selection_before_switch": Path(json.loads(config.read_bytes())["data_dir"]).resolve() == root.resolve(),
                "target_inside_installation": restored_root.resolve().is_relative_to(root.resolve()),
                "target_alias_matches_migration": restored_session.get("keyring_account") == alias,
                "target_backend": restored_session.get("keyring_backend") in ("native", "secret_service", "kernel"),
                "target_inline_factors": any(key in restored_session for key in ("super", "pass", "secret", "secret_key")),
                "target_primary_credential": migration_keys._read("rsrs", "super:" + alias) is not None,
            }
            selected = json.loads(cli("--json", "account", "use", "recovered-original").stdout)["summary"]
            require(Path(selected["dir"]).resolve() == restored_root.resolve(), "original_profile_selection_failed")
            profiles = json.loads(cli("--json", "account", "list").stdout)["details"]["accounts"]
            selected_profiles = [row for row in profiles if row["current"]]
            require(len(selected_profiles) == 1 and selected_profiles[0]["name"] == "recovered-original"
                    and Path(selected_profiles[0]["dir"]).resolve() == restored_root.resolve(),
                    "original_profile_selection_failed")
            report["stage"] = "legacy_recovery_migrate_vault"
            cli(*migration)
            if fixture_witness is not None:
                report["stage"] = "legacy_recovery_verify_witness"
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
            report["stage"] = "server_transfer_list_accounts"
            source_profile = json.loads(cli("--json", "account", "list").stdout)["details"]["accounts"]
            source_account = next(row for row in source_profile if row["current"])
            source_name = source_account["name"]
            source_path = Path(source_account["dir"])
            source_session = source_path / "session.json"
            report["stage"] = "legacy_recovery_stop_runtime"
            cli("--runtime-internal", "--stop")
            source_value = json.loads(source_session.read_bytes())
            source_value["addr"] = "https://previous.invalid"
            # Keep the current source's native custody; inline factors plus the
            # existing login journal are rejected before a transfer is admitted.
            require(all(field not in source_value for field in ("super", "pass", "secret", "secret_key")),
                    "server_transfer_changed_source")
            source_session.write_text(json.dumps(source_value), encoding="utf-8")
            with sqlite3.connect((source_path / "rsrs.db").as_uri() + "?mode=ro", uri=True) as db:
                source_before = source_session.read_bytes(), db.execute("SELECT id,ciphertext,nonce FROM memories ORDER BY id").fetchall()
            cloud_urk = secrets.token_bytes(32)
            cloud_salt, cloud_nonce = secrets.token_hex(16), secrets.token_bytes(12)
            state["vault"] = {"version": 4, "kdf_salt": cloud_salt, "urk_nonce": cloud_nonce.hex(),
                "wrapped_urk": legacy.PREFIX + AESGCM(legacy.v4_kek(code, cloud_salt, legacy.PREFIX)).encrypt(cloud_nonce, cloud_urk, None).hex()}
            report["transfer_http"] = []
            state.update(sync_blobs={}, sync_pulls=0, transfer_stage="initial_login",
                         transfer_http=report["transfer_http"])
            # Keep the fresh cloud vault separate from main's existing remote identity.
            transfer_addr = f"http://localhost:{server.server_port}"
            transfer = ("--json", "login", "--interactive", "--addr", transfer_addr, "--user", "synthetic",
                        "--pass=synthetic-password", "--super", code, "--migrate-local")
            report["stage"] = "server_transfer_initial_login"
            first_result = cli(*transfer, success=False)
            report["transfer_initial_response"] = {"exit_code": first_result.returncode,
                "diagnostic": safe_cli_diagnostic(first_result.stdout, first_result.stderr),
                "sync_pulls": state["sync_pulls"], "synced_records": len(state["sync_blobs"])}
            require(any(event == {"stage": "initial_login", "method": "POST",
                        "route": "/push/batch", "status": 503} for event in state["transfer_http"]),
                    "server_transfer_fault_not_observed")
            require(first_result.returncode == 2, "server_transfer_sync_warning_missing")
            first = json.loads(first_result.stdout)["summary"]
            require(first["sync"]["status"] == "pending"
                    and first["sync"]["reason"] == "post_import_sync_failed",
                    "server_transfer_sync_warning_missing")
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
            report["stage"] = "server_transfer_select_source"
            state["transfer_stage"] = "select_source"
            cli("--json", "account", "use", source_name)
            report["stage"] = "server_transfer_retry_login"
            state["transfer_stage"] = "retry_login"
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
        except BaseException as error:
            report["operation_failure_code"] = (str(error) if type(error) is RuntimeError
                and str(error) in FAILURE_CODES else "unclassified_failure")
            raise
        finally:
            report["failure_stage"] = report["stage"]
            report["stage"] = "owned_child_cleanup"
            if child is not None:
                child_running = child.poll() is None
                members = process_group_members(child.pid)
                report["cleanup_snapshot"] = {"child_running": child_running,
                    "members": len(members), "helpers": sum(row["control_helper"] for row in members.values()),
                    "zombies": sum(row["state"] == "Z" for row in members.values())}
                if child_running:
                    stop_owned_control(child)
                try:
                    stdout, stderr = child.communicate(timeout=15)
                except subprocess.TimeoutExpired as error:
                    stdout = error.output or b""
                    stderr = error.stderr or b""
                except OSError:
                    stdout = b""
                    stderr = b""
                report["migration_child"] = {"exit_code": child.returncode,
                    "migration_stage": None, "migration_exchange": None, "register_kind": None,
                    "diagnostic": safe_cli_diagnostic(stdout, stderr), "operation_phase": None}
                report["fixture_requests"] = {name: state.get(name, 0)
                    for name in ("gets", "posts", "logins", "password_posts")}
                try:
                    value = json.loads(stdout)
                except (ValueError, UnicodeError, RecursionError):
                    value = None
                # Observe only this response's owned journal; never recover or replay it.
                try:
                    details = value.get("details") if isinstance(value, dict) else None
                    operation_id = details.get("operation_id") if isinstance(details, dict) else None
                    source = details.get("source_profile") if isinstance(details, dict) else None
                    if (isinstance(operation_id, str) and str(uuid.UUID(operation_id)) == operation_id
                            and uuid.UUID(operation_id).version == 4 and isinstance(source, str)
                            and Path(source).resolve() == root.resolve()
                            and not recovery_path.is_symlink()
                            and recovery_path.resolve(strict=True) == root.resolve() / ".login-recovery.json"):
                        journal = json.loads(recovery_path.read_bytes())
                        records = [row for row in journal.get("operations", [])
                            if isinstance(row, dict) and row.get("operation_id") == operation_id]
                        if (journal.get("schema_version") == 2 and len(records) == 1
                                and (journal.get("active") or {}).get("operation_id") == operation_id):
                            record = records[0]
                            phase = record.get("phase")
                            if (record.get("idempotency_key") == operation_id
                                    and (journal.get("active") or {}).get("alias") == record.get("alias")
                                    and re.fullmatch(r"login-[a-f0-9]{32}", record.get("alias", "")) is not None
                                    and record.get("root") == str(root.resolve())
                                    and record.get("profile") == str(root.resolve())
                                    and phase in ("admitted", "login_input", "remote_pending", "remote_unknown",
                                        "authorized", "prepared", "awaiting_verification", "rolling_back",
                                        "committed", "rolled_back")):
                                report["migration_child"]["operation_phase"] = phase
                except (OSError, ValueError, TypeError, AttributeError, RecursionError):
                    pass  # Diagnostic absence cannot replace the original fixture failure.
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
                if not child_running:
                    stop_owned_control(child)
            # Never unblock a request while a surviving private helper can publish it.
            release.set()
            report["stage"] = "runtime_cleanup"
            stopped = subprocess.run([str(args.binary), "--runtime-internal", "--stop"], env=env, capture_output=True, timeout=60)
            report["runtime_cleanup"] = {"passed": stopped.returncode in (0, 2)}
            report["stage"] = "credential_cleanup"
            if keys:
                # Discover interrupted aliases only from our synthetic files, including
                # failures before a barrier. Never claim arbitrary credential-store items.
                for path in args.root.rglob("*.json"):
                    if path.name.startswith("account-login-"):
                        custody = json.loads(path.read_bytes())
                        operation_id = custody["operation_id"]
                        parsed = uuid.UUID(operation_id)
                        require(parsed.version == 4 and str(parsed) == operation_id
                                and path == Path(custody["root"]) / "runtime/autostart" / ("account-login-" + operation_id + ".json")
                                and all(Path(custody[key]).resolve().is_relative_to(args.root.resolve())
                                        for key in ("root", "source"))
                                and custody["account"] == "login-" + parsed.hex
                                and custody["backend"] == "secret_service", "unowned_fixture_login_custody")
                        native_aliases.add(custody["account"])
                        continue
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
                    require(attributes.get("service") == "rsrs" and re.fullmatch(r"(?:(?:super|pass):(?:login-[a-f0-9]{32}|legacy-[a-f0-9]{16})|(?:login-control|key-control):login-[a-f0-9]{32})", attributes.get("username", "")), "unexpected_private_credential")
                    require(attributes["username"].split(":", 1)[1] in native_aliases,
                            "credential_not_bound_to_fixture_transaction")
                    item.delete()
                require(not list(keys.collection.get_all_items()), "native_fixture_cleanup_failed")
                report["native_cleanup"] = keys.cleanup()
            elif migration_keys:
                report["native_cleanup"] = migration_keys.cleanup()
            report["stage"] = "server_cleanup"
            server.shutdown()
            server.server_close()
            report["server_cleanup"] = {"passed": True, "scope": "loopback_fixture"}
        require(report["runtime_cleanup"]["passed"], "owned_runtime_cleanup_failed")
        if migration_keys or keys:
            require(report["native_cleanup"]["passed"], "native_fixture_cleanup_failed")
        report["stage"] = "complete"
        print(json.dumps(report))


if __name__ == "__main__":
    try:
        if "--gui-recovery-server" in sys.argv:
            gui_recovery_server()
        else:
            main()
    except Exception:
        # Details are available only as bounded codes in the owned report.
        raise SystemExit("login_interruption_fixture_failed") from None
