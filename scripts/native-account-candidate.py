#!/usr/bin/env python3
"""Run the unchanged Runtime account regression against two exact source commits.

The default retains the account case; --suite full runs every original business case.
The fixed diagnostic-failures suite isolates four known failures and is not release acceptance.
Only sanitized identity and result JSON is publishable. Product output stays in
private runner-temporary logs, including on failures. This is not release proof.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import time
import tomllib

TARGET = "x86_64-unknown-linux-gnu"
CASE = "account::authorization_preserves_and_commits_profiles"
MODULE_COUNTS = {"memory_revision": 6, "diary_identity": 11, "snapshot_lifecycle": 8,
                 "account": 3, "capture_main": 2}
NATIVE_STOP_CASE = "diary_identity::native_stop_waits_and_explicit_force_reaps_real_core_without_replay"
BASELINE_CASES = (
    CASE,
    "account::space_create_list_use_remove",
    "account::spaces_coordinate_with_the_owned_runtime",
    "capture_main::memory_revision_without_runtime_fails_without_local_business_fallback",
    "capture_main::residual_host_and_parser_errors_remain_user_errors",
    "diary_identity::canonical_identity_merges_legacy_tracks_without_touching_other_users_or_days",
    "diary_identity::concurrent_same_day_client_commands_preserve_each_successful_addition_once",
    "diary_identity::deleted_stable_track_uses_legacy_fallback_and_deleted_history_is_not_resurrected",
    "diary_identity::environment_key_fallback_does_not_adopt_unlocked_profile_alias",
    "diary_identity::explicit_titles_preserve_entries_and_leave_the_daily_track_unchanged",
    "diary_identity::important_remember_pending_candidates_preserve_ciphertext_and_outbox",
    "diary_identity::missing_entry_and_usage_failures_have_machine_diagnostics",
    "diary_identity::old_owner_normalized_diary_keeps_its_author_after_public_title_edit",
    "diary_identity::public_title_edit_and_blank_title_still_append_without_changing_metadata",
    "diary_identity::remember_public_payload_covers_created_appended_and_merged",
    "diary_identity::unrelated_canonical_author_fails_without_writes_or_private_output",
    "memory_revision::memory_revision_direct_is_model_free_and_follows_resolved_profile",
    "memory_revision::memory_revision_direct_respects_client_only_policy",
    "memory_revision::memory_revision_does_not_initialize_or_autostart",
    "memory_revision::memory_revision_does_not_recover_interrupted_login",
    "memory_revision::memory_revision_legacy_database_and_ambiguous_names",
    "memory_revision::memory_revision_preserves_legacy_environment_alias",
    "snapshot_lifecycle::concurrent_host_recover_cannot_interleave_with_restore_commit",
    "snapshot_lifecycle::healthy_snapshot_rescue_preserves_unparseable_current_witness",
    "snapshot_lifecycle::public_empty_recall_returns_its_query_log_identity",
    "snapshot_lifecycle::public_feedback_attribution_uses_exact_request_and_refuses_readonly_writes",
    "snapshot_lifecycle::public_snapshot_restore_reopens_runtime_and_keeps_sync_quarantined",
    "snapshot_lifecycle::public_witness_verifies_restored_chain_and_reports_tamper_without_writes",
    "snapshot_lifecycle::queued_direct_resume_rechecks_maintenance_after_library_ownership_wait",
    "snapshot_lifecycle::staged_store_open_failure_cannot_pass_boot_readiness_and_is_recoverable",
)
# This explicit remote subset excludes the diary diagnostic case containing --direct.
# The concurrent case also checks candidate HTTP idempotency directly; those checks
# are candidate Runtime evidence, not requests made by the stable CLI.
STABLE_DIARY_CASES = tuple(case for case in BASELINE_CASES
    if case.startswith("diary_identity::")
    and case != "diary_identity::missing_entry_and_usage_failures_have_machine_diagnostics")
STABLE_ASSETS = {
    "rsrs-x86_64-unknown-linux-gnu": (52491808, "c03c131c61819a5f4d132cfe328f7c1da82c2f0b21a9c87d2b8870d1541a4c3e"),
    "cli-build-x86_64-unknown-linux-gnu.json": (437, "e211d241e24408b238d994114d7c89c5e77af89fc185aaf0e4fe1c9c4ff884b2"),
    "rsrs-x86_64-unknown-linux-gnu-runtime.tar.gz": (546198, "aa4437c33089c79376410af2b83e4889a4a10b2058eed43094ddb1f40406821d"),
}
DIAGNOSTIC_CASES = (
    CASE,
    "account::spaces_coordinate_with_the_owned_runtime",
    "snapshot_lifecycle::healthy_snapshot_rescue_preserves_unparseable_current_witness",
    "snapshot_lifecycle::public_witness_verifies_restored_chain_and_reports_tamper_without_writes",
)


def selected_cases(listing, suite, require_native_stop=False):
    require(not require_native_stop or suite == "full", "native_stop_requires_full_suite")
    names = [line[:-6] for line in listing.splitlines() if line.endswith(": test")]
    require(names.count(CASE) == 1, "original_account_case_missing")
    if suite == "account":
        return [CASE]
    if suite == "stable-diary-remote":
        require(len(STABLE_DIARY_CASES) == 10
                and all(names.count(case) == 1 for case in STABLE_DIARY_CASES),
                "stable_diary_case_inventory_mismatch")
        return list(STABLE_DIARY_CASES)
    if suite == "diagnostic-failures":
        require(all(names.count(case) == 1 for case in DIAGNOSTIC_CASES), "diagnostic_case_inventory_mismatch")
        return list(DIAGNOSTIC_CASES)
    if suite == "diagnostic-native-stop":
        require(names.count(NATIVE_STOP_CASE) == 1, "native_stop_business_case_missing")
        return [NATIVE_STOP_CASE]
    require(suite == "full", "unknown_business_suite")
    expected = set(BASELINE_CASES)
    if NATIVE_STOP_CASE in names:
        expected.add(NATIVE_STOP_CASE)
    require(len(names) == len(set(names)) == sum(MODULE_COUNTS.values()) + int(NATIVE_STOP_CASE in expected)
            and set(names) == expected, "business_case_inventory_mismatch")
    require(not require_native_stop or NATIVE_STOP_CASE in expected, "native_stop_business_case_missing")
    return names

def compatibility_host_checks(captured):
    checks = []
    marker = b"client2-account-host "
    for line in captured.splitlines():
        if marker not in line:
            continue
        try:
            value = json.loads(line.split(marker, 1)[1])
        except (ValueError, UnicodeDecodeError):
            return None
        if (not isinstance(value, dict) or set(value) != {"stage", "passed"}
                or value["stage"] not in ("space-profile", "import-target", "restart-target")
                or type(value["passed"]) is not bool):
            return None
        checks.append(value)
    return checks


def safe_failure_diagnostics(captured, failed_cases):
    # Rebuild fixed fields only. Never publish arbitrary errors, paths, journal
    # values or output text, including when a diagnostic event is malformed.
    enums = {
        "reason_code": {None, "account_outcome_unknown", "runtime_error", "redacted"},
        "error_type": {None, "outcome_unknown", "runtime", "redacted"},
        "runtime_log_reason_code": {"not_captured_by_fixture"},
        "journal_reason_code": {"read", "invalid_json", "not_found", "permission_denied", "io_error"},
        "phase": {None, "admitted", "login_input", "remote_pending", "remote_unknown", "authorized",
                  "prepared", "awaiting_verification", "rolling_back", "committed", "rolled_back", "redacted"},
        "backend": {None, "native", "secret_service", "kernel", "redacted"},
    }
    booleans = {"journal_schema_v2", "active_present", "active_matches_operation",
                "root_matches_fixture", "source_matches_fixture", "candidate_present",
                "candidate_sha256_present", "authorization_present", "vault_present", "target_present"}
    nullable_booleans = {"published_vault", "vault_pending", "import_started", "sync_started",
                         "publication_pending", "publication_done", "vault_done", "password_done", "owns_config"}
    arrays = {"backends", "pass_backends", "totp_backends"}
    base = {"schema_version", "event", "reason_code", "error_type", "operation_id", "runtime_log_reason_code"}
    allowed = base | set(enums) | booleans | nullable_booleans | arrays | {"journal_os_error_code", "matching_records"}
    events, invalid, seen = [], False, 0
    for line in captured.splitlines():
        if b'"authorization_failure_evidence"' not in line:
            continue
        seen += 1
        if seen > 16:
            invalid = True
            break
        try:
            event = json.loads(line[line.index(b"{"):])
            if (not isinstance(event, dict) or not base.issubset(event) or set(event) - allowed
                    or type(event["schema_version"]) is not int or event["schema_version"] != 1
                    or event["event"] != "authorization_failure_evidence"):
                raise ValueError
            clean = {"schema_version": 1, "event": "authorization_failure_evidence"}
            for key, choices in enums.items():
                if key in event:
                    value = event[key]
                    if value is not None and not isinstance(value, str):
                        raise ValueError
                    if value not in choices:
                        raise ValueError
                    clean[key] = value
            for key in booleans | nullable_booleans:
                if key in event:
                    value = event[key]
                    if type(value) is not bool and not (key in nullable_booleans and value is None):
                        raise ValueError
                    clean[key] = value
            for key in arrays:
                if key in event:
                    value = event[key]
                    if value is not None and (not isinstance(value, list) or len(value) > 16
                            or any(item is not None and (not isinstance(item, str)
                                or item not in enums["backend"]) for item in value)):
                        raise ValueError
                    clean[key] = value
            for key in ("journal_os_error_code", "matching_records"):
                if key in event:
                    value = event[key]
                    if not (key == "journal_os_error_code" and value is None):
                        if type(value) is not int or not (-2147483648 <= value <= 2147483647):
                            raise ValueError
                        if key == "matching_records" and not 0 <= value <= 1024:
                            raise ValueError
                    clean[key] = value
            operation = event["operation_id"]
            if operation is not None and (not isinstance(operation, str) or not re.fullmatch(
                    r"[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}", operation)):
                raise ValueError
            clean["operation_id_present"] = operation is not None
            events.append(clean)
        except (ValueError, TypeError):
            invalid = True

    known = {
        b"authorized OAuth login failed": "account_authorized_login_failed",
        b"owned space command": "account_owned_space_command_failed",
        b"join never fetched": "account_join_request_not_observed",
        b"join did not authenticate its ordered GET": "account_join_authorization_mismatch",
        b"unverifiable witness prevented healthy rescue": "snapshot_unverifiable_rescue_failed",
        b"restore of witnessed library failed": "snapshot_witness_restore_failed",
        b"healthy witness snapshot rescue failed": "snapshot_witness_rescue_failed",
        b"expected witness checkpoint rejection": "snapshot_checkpoint_rejection_mismatch",
        b"expected diagnostic copy rejection": "snapshot_diagnostic_rejection_mismatch",
        b"account committed; Runtime host handoff is pending": "account_handoff_pending",
        b"operation committed and maintenance finished; Client2 compatibility handoff pending": "compatibility_handoff_pending",
        b"model owner differs from the installed Runtime, account, profile or registration": "compatibility_owner_binding_mismatch",
        b"compatibility handoff cannot inherit maintenance authorization": "compatibility_maintenance_token_present",
        b"compatibility handoff requires an unregistered host and completed durable maintenance": "compatibility_maintenance_not_finished",
        b"Client2 requires the same verified CLI bytes at the stable bin path": "compatibility_stable_cli_mismatch",
        b"compatibility handoff owner did not fully drain": "compatibility_owner_drain_incomplete",
        b"compatibility host readiness identity mismatch": "compatibility_host_identity_mismatch",
        b"compatibility host is not the verified OS listener": "compatibility_listener_mismatch",
        b"claimed compatibility host does not own the OS listener": "compatibility_listener_mismatch",
        b"compatibility loopback listener ownership is unavailable or ambiguous": "compatibility_listener_unverified",
        b"compatibility loopback listener is unavailable or ambiguous": "compatibility_listener_unverified",
        b"compatibility listener is not the stable CLI image": "compatibility_host_image_mismatch",
        b"compatibility host identity does not match this installation": "compatibility_host_identity_mismatch",
        b"compatibility host backend binding changed": "compatibility_backend_binding_mismatch",
        b"compatibility backend OS process changed": "compatibility_backend_process_mismatch",
        b"compatibility startup is uncertain for child": "compatibility_startup_uncertain",
        b"compatibility Runtime failed independent committed-owner handoff verification": "compatibility_restored_owner_mismatch",
        b"host control request frame exceeds the protocol limit": "control_request_frame_limit",
        b"cannot start owned host control Runtime": "control_helper_spawn_failed",
        b"missing host control input pipe": "control_input_pipe_missing",
        b"missing host control output pipe": "control_output_pipe_missing",
        b"host control input owner was released": "control_input_owner_released",
        b"host control request write failed": "control_request_write_failed",
        b"missing host control response frame": "control_response_frame_missing",
        b"invalid host control response frame size": "control_response_frame_size_invalid",
        b"incomplete host control response frame": "control_response_frame_incomplete",
        b"invalid host control response JSON": "control_response_json_invalid",
        b"extra host control response bytes": "control_response_extra_bytes",
        b"host control response deadline or channel failure": "control_response_channel_failed",
        b"host control response deadline exceeded": "control_response_deadline_exceeded",
        b"host control exit deadline exceeded": "control_exit_deadline_exceeded",
        b"host control Runtime exit does not match its response": "control_exit_response_mismatch",
        b"host control response identity mismatch": "control_response_identity_mismatch",
        b"host control data directory mismatch": "control_response_profile_mismatch",
        b"missing host control result envelope": "control_result_envelope_missing",
        b"host control authorization was not confirmed": "control_authorization_unconfirmed",
        b"host control I/O worker did not finish": "control_io_cleanup_incomplete",
        b"host control I/O worker panicked": "control_io_worker_panicked",
        b"auth control image or identity changed while preparing authorization": "auth_control_grant_identity_changed",
        b"account control response identity mismatch": "account_control_response_identity_mismatch",
        b"account launch or parent authorization failed": "account_control_parent_unauthorized",
        b"account control binding changed or does not match": "account_control_binding_mismatch",
        b"account controller is unavailable": "account_control_unavailable",
        b"account deadline or parent authorization ended": "account_control_deadline_or_parent_ended",
        b"snapshot control requires matching takeover, image and maintenance grant": "snapshot_control_grant_binding_mismatch",
        b"snapshot maintenance grant missing": "snapshot_control_grant_missing",
        b"snapshot response identity mismatch": "snapshot_control_response_identity_mismatch",
        b"snapshot response profile missing": "snapshot_control_response_profile_missing",
        b"snapshot response profile mismatch": "snapshot_control_response_profile_mismatch",
        b"snapshot Runtime did not confirm a receipt": "snapshot_remote_receipt_unconfirmed",
        b"snapshot control readiness mismatch": "snapshot_control_readiness_mismatch",
        b"snapshot result missing": "snapshot_control_result_missing",
        b"invalid snapshot receipt shape": "snapshot_control_receipt_invalid",
        b"snapshot receipt does not identify the original request": "snapshot_control_receipt_request_mismatch",
        b"snapshot witness checkpoint is unverifiable; diagnostic copy cannot be a restore target": "snapshot_witness_diagnostic_copy_rejected",
        b"snapshot witness checkpoint mismatch or missing checkpoint": "snapshot_witness_checkpoint_mismatch",
        b"snapshot witness checkpoint exists without a witness schema": "snapshot_witness_schema_missing",
        b"snapshot requires this controller's exact Paused marker": "snapshot_paused_marker_mismatch",
        b"snapshot finalization requires this controller's exact Verified marker": "snapshot_verified_marker_mismatch",
        b"snapshot maintenance marker missing": "snapshot_marker_missing",
        b"snapshot maintenance ownership missing": "snapshot_marker_ownership_missing",
        b"snapshot marker changed during drain": "snapshot_marker_changed_during_drain",
        b"snapshot operation or drained owner changed": "snapshot_drained_owner_changed",
        b"snapshot has no authenticated drain capability": "snapshot_drain_capability_missing",
        b"snapshot drain account differs from original operation": "snapshot_drain_account_mismatch",
        b"snapshot drained owner is still alive": "snapshot_drained_owner_alive",
        b"snapshot owner is alive but health is unavailable; drain proof required": "snapshot_live_owner_without_health",
        b"snapshot supervisor is still running; explicit drain is required": "snapshot_supervisor_still_running",
        b"snapshot endpoint is not a bounded regular file": "snapshot_endpoint_invalid_file",
        b"snapshot endpoint too large": "snapshot_endpoint_too_large",
        b"snapshot endpoint owner PID missing": "snapshot_endpoint_pid_missing",
        b"snapshot endpoint changed since offline fencing": "snapshot_endpoint_changed",
        b"drained runtime supervisor is still active or its endpoint changed": "runtime_supervisor_or_endpoint_changed",
        b"runtime endpoint owner changed after drain": "runtime_endpoint_changed_after_drain",
        b"snapshot restore exchange failed": "snapshot_restore_exchange_failed",
        b"snapshot restore is not Installed": "snapshot_restore_not_installed",
        b"snapshot startup/verification failed": "snapshot_startup_verification_failed",
        b"snapshot startup failed; recovery remains pending": "snapshot_startup_recovery_pending",
        b"snapshot commit outcome unknown": "snapshot_commit_outcome_unknown",
        b"snapshot commit not confirmed": "snapshot_commit_unconfirmed",
        b"compatibility request failed; outcome may be unknown; do not replay": "compatibility_proxy_outcome_unknown",
        b"runtime process start identity does not match health": "runtime_stop_identity_mismatch",
        b"runtime drain is still pending; no process was forced to exit": "runtime_drain_pending",
        b"stopped runtime has not released its library lock": "runtime_library_lock_retained",
        b"snapshot transaction completed; host maintenance cleanup pending": "snapshot_host_cleanup_pending",
        b"snapshot transaction completed; cleanup pending": "snapshot_cleanup_pending",
    }
    # libtest prints private failure output under exact, known case headers.
    # Ignore success output and unrelated text, which may contain expected errors.
    blocks, current, in_failures = {}, None, False
    for line in captured.splitlines():
        if line == b"failures:":
            in_failures, current = True, None
            continue
        if line == b"successes:" or line.startswith(b"test result:"):
            in_failures, current = False, None
        if in_failures and line.startswith(b"---- ") and line.endswith(b" stdout ----"):
            current = next((case for case in failed_cases
                            if line == b"---- " + case.encode() + b" stdout ----"), None)
            if current is not None:
                blocks[current] = []
        elif in_failures and current is not None:
            blocks[current].append(line)
    response_reasons = {None, "auth_outcome_unknown", "identity_write_recovery_required",
                        "key_outcome_unknown", "account_handoff_pending", "account_outcome_unknown",
                        "request_outcome_unknown", "invalid_input", "runtime_error"}
    response_error_types = {None, "outcome_unknown", "identity_write_recovery_required",
                            "handoff_pending", "user", "runtime"}
    response_events, response_invalid, response_seen = [], False, 0
    response_marker = b"account-response-evidence "
    for case in failed_cases:
        for line in blocks.get(case, []):
            if response_marker not in line:
                continue
            response_seen += 1
            if response_seen > 16:
                response_invalid = True
                break
            try:
                if not line.startswith(response_marker) or len(line) > 16384:
                    raise ValueError
                response = json.loads(line[len(response_marker):])
                if (not isinstance(response, dict)
                        or set(response) != {"stage", "reason_code", "error_type"}
                        or not isinstance(response["stage"], str)
                        or response["stage"] not in {"required_input", "wrong_super", "space_command"}):
                    raise ValueError
                clean = {"case": case, "stage": response["stage"]}
                for key, choices in (("reason_code", response_reasons), ("error_type", response_error_types)):
                    value = response[key]
                    if value is not None and not isinstance(value, str):
                        raise ValueError
                    clean[key] = value if value in choices else "redacted"
                response_events.append(clean)
            except (ValueError, TypeError):
                response_invalid = True
    codes, locations = {}, {}
    for case in failed_cases:
        block = b"\n".join(blocks.get(case, []))
        codes[case] = list(dict.fromkeys(code for text, code in known.items() if text in block)) or ["unknown_private_failure"]
        locations[case] = []
        for line in blocks.get(case, []):
            if b"panicked at " not in line or len(line) > 8192:
                continue
            for match in re.finditer(rb"[/\\](account\.rs|snapshot_lifecycle\.rs|diary_identity\.rs):([0-9]{1,6}):([0-9]{1,4}):", line):
                number, column = int(match[2]), int(match[3])
                if not (1 <= number <= 20000 and 1 <= column <= 4096):
                    continue
                location = {"file": match[1].decode("ascii"), "line": number, "column": column}
                if location not in locations[case] and len(locations[case]) < 8:
                    locations[case].append(location)
    native_stages = {b"start", b"fixture_ready", b"memory_seeded", b"runtime_ready",
                     b"provider_received", b"active_verified", b"stop_accepted",
                     b"force_identities_rejected", b"worker_reaped", b"normal_waited",
                     b"same_key_checked", b"business_completed", b"runtime_stopped",
                     b"store_unchanged", b"restarted", b"stale_rejected", b"restart_stopped", b"complete"}
    checkpoints, checkpoint_invalid = [], False
    for line in blocks.get(NATIVE_STOP_CASE, []):
        if b"NATIVE_STOP_CHECKPOINT" not in line:
            continue
        match = re.fullmatch(rb"NATIVE_STOP_CHECKPOINT mode=(normal|forced) stage=([a-z_]{1,32})", line)
        if match is None or match[2] not in native_stages:
            checkpoint_invalid = True
            continue
        checkpoint = {"mode": match[1].decode("ascii"), "stage": match[2].decode("ascii")}
        if checkpoint not in checkpoints:
            if len(checkpoints) >= 36:
                checkpoint_invalid = True
                continue
            checkpoints.append(checkpoint)
    return {"authorization_events": events, "authorization_event_invalid": invalid,
            "failure_codes": codes, "failure_locations": locations,
            "response_events": response_events, "response_event_invalid": response_invalid,
            "native_stop_checkpoints": checkpoints, "native_stop_checkpoint_invalid": checkpoint_invalid}


MODEL_HASHES = {
    "tokenizer.json": "6710678b12670bc442b99edc952c4d996ae309a7020c1fa0096dd245c2faf790",
    "onnx/model_quantized.onnx": "0826f8c1ab9edf1801db86c61919d4d108e8bfc0b809ec823ad366882ff0b77d",
    "onnx/model_quantized.cpu-v1.ort": "7ff152e912bc234f5c90e4012f99897a7b2ce180f016db2321304057756b64ff",
}


def require(value, code):
    if not value:
        raise RuntimeError(code)


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def verify_source(source, sha):
    require(re.fullmatch(r"[a-f0-9]{40}", sha), "exact_source_sha_required")
    head = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
    require(head == sha, "source_head_mismatch")
    subprocess.run(["git", "-C", str(source), "diff", "--exit-code", "HEAD", "--"],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def source_version(source, package):
    version = tomllib.loads((source / package / "Cargo.toml").read_text())["package"]["version"]
    require(re.fullmatch(r"\d+\.\d+\.\d+-dev\.\d+", version), "candidate_dev_version_required")
    return version


def official_cli_version(metadata_path, cli, source_sha, env):
    # Official publication applies an ephemeral version without editing the tagged source.
    require(source_sha == "425f397db2a64347d3d27fa93db630fad6b9b520",
            "official_cli_source_mismatch")
    metadata_path = Path(metadata_path)
    require(metadata_path.name == "cli-build-x86_64-unknown-linux-gnu.json"
            and not metadata_path.is_symlink() and metadata_path.is_file()
            and metadata_path.stat().st_size == 427
            and digest(metadata_path) == "243a679da8b9436b7a6e5e09a5e4f113ad09e4d64e9166f50e6a10105c45619b",
            "official_cli_metadata_digest_mismatch")
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    expected = {"schema_version": 2, "artifact_layout": "cli-frontend-v2",
                "git_sha": source_sha, "version": "1.0.21-dev.6", "target": TARGET,
                "binary_file": "rsrs-x86_64-unknown-linux-gnu", "binary_size": 14133456,
                "binary_sha256": "f82eef533b906dd5ed5e96ebe17321571084ff138c29acdc92f55ebb8a8ecf2e"}
    require(all(metadata.get(key) == value for key, value in expected.items()),
            "official_cli_metadata_identity_mismatch")
    require(cli.stat().st_size == metadata["binary_size"]
            and digest(cli) == metadata["binary_sha256"], "official_cli_binary_mismatch")
    version = metadata["version"]
    actual = subprocess.check_output([str(cli), "--version"], env=env,
                                     stderr=subprocess.PIPE, timeout=30)
    require(version.encode() in actual.split(), "official_cli_version_mismatch")
    return version


def stable_business_identity(cli, metadata_path, archive, env=None):
    # Fixed schema-1 release only. It never replaces the candidate's manager CLI.
    paths = (Path(cli), Path(metadata_path), Path(archive))
    require(len({path.parent.resolve() for path in paths}) == 1,
            "stable_business_assets_must_be_adjacent")
    for path, name in zip(paths, STABLE_ASSETS):
        size, expected_hash = STABLE_ASSETS[name]
        require(path.name == name and not path.is_symlink() and path.is_file()
                and path.stat().st_size == size and digest(path) == expected_hash,
                "stable_business_asset_mismatch")
    cli, metadata_path, archive = paths
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    expected = {"schema_version": 1, "git_sha": "26ead1ecf5c1a41e6d5e518aeb375e896f6c4c9e",
                "version": "1.0.20", "target": TARGET, "binary_file": cli.name,
                "runtime_file": archive.name, "binary_sha256": STABLE_ASSETS[cli.name][1],
                "runtime_sha256": STABLE_ASSETS[archive.name][1]}
    require(metadata == expected, "stable_business_metadata_identity_mismatch")
    with tarfile.open(archive, "r:gz") as bundle:
        names = set()
        for member in bundle.getmembers():
            name = member.name.rstrip("/")
            require(name and not name.startswith("/")
                    and not any(part in ("", ".", "..") for part in name.split("/"))
                    and not any(character in name for character in "\\:\0")
                    and (member.isfile() or member.isdir())
                    and (name == "core-runtime.json" or name == "core-notices"
                         or name.startswith("core-notices/"))
                    and name not in names, "stable_business_archive_member_rejected")
            names.add(name)
        require("core-runtime.json" in names, "stable_business_core_metadata_missing")
        core_stream = bundle.extractfile("core-runtime.json")
        require(core_stream is not None, "stable_business_core_metadata_missing")
        with core_stream:
            core = json.load(core_stream)
        require(core.get("schema_version") == 1 and core.get("target") == TARGET,
                "stable_business_core_identity_mismatch")
    if env is not None:
        actual = subprocess.check_output([str(cli), "--version"], env=env,
                                         stderr=subprocess.PIPE, timeout=30)
        require(b"1.0.20" in actual.split(), "stable_business_version_mismatch")
    return {"version": "1.0.20", "source_sha": expected["git_sha"], "target": TARGET,
            "binary_sha256": digest(cli), "metadata_sha256": digest(metadata_path),
            "runtime_archive_sha256": digest(archive),
            "scope": "ten_remote_diary_cases_not_all_stable_features",
            "concurrent_http_checks": "candidate_runtime_only"}


def safe_file(root, relative):
    require(isinstance(relative, str) and relative and not relative.startswith("/")
            and not any(part in ("", ".", "..") for part in relative.split("/"))
            and not any(character in relative for character in "\\:\0"), "unsafe_payload_path")
    path = root
    for part in relative.split("/"):
        path = path / part
        require(not path.is_symlink(), "linked_payload_rejected")
    require(path.is_file(), "payload_file_missing")
    return path


def package_runtime(runtime, staged, destination, version, runtime_sha, cli_sha, cli_hash, cli_version):
    destination.mkdir(mode=0o700)
    payload = destination / "payload"
    payload.mkdir(mode=0o700)
    binary_name = f"rsrs-runtime-{TARGET}"
    core_path = safe_file(staged, "core-runtime.json")
    core = json.loads(core_path.read_text())
    require(core.get("schema_version") == 1 and core.get("target") == TARGET,
            "core_target_mismatch")
    shutil.copy2(runtime, payload / binary_name)
    shutil.copy2(core_path, payload / "core-runtime.json")
    paths = {binary_name, "core-runtime.json"}
    for entry in core["files"]:
        relative = entry["path"]
        require(relative not in paths, "duplicate_payload_path")
        source = safe_file(staged, relative)
        require(source.stat().st_size == entry["size"] and digest(source) == entry["sha256"],
                "staged_core_digest_mismatch")
        paths.add(relative)
        target = payload / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    inventory = [{"path": name, "size": (payload / name).stat().st_size,
                  "sha256": digest(payload / name)} for name in sorted(paths)]
    archive = destination / f"rsrs-runtime-{TARGET}.tar.gz"
    with tarfile.open(archive, "w:gz", format=tarfile.USTAR_FORMAT) as stream:
        for name in sorted(paths):
            stream.add(payload / name, arcname=name, recursive=False)
    metadata = {
        "schema_version": 2, "runtime_version": version, "tag": "v" + version,
        "channel": "dev", "target_triple": TARGET, "archive_file": archive.name,
        "archive_sha256": digest(archive), "binary_file": binary_name,
        "binary_sha256": digest(runtime), "source_commit": runtime_sha,
        "compat": {"min_cli": cli_version, "max_cli": "*"},
        "protocol_range": {"minimum": 1, "maximum": 1},
        "capabilities": {"business_executor": "1", "mcp_server": "1"},
        "files": inventory,
        "candidate": {"kind": "unpublished-source-fixture", "cli_source_sha": cli_sha,
                      "cli_binary_sha256": cli_hash},
    }
    metadata_path = destination / f"runtime-build-{TARGET}.json"
    write_json(metadata_path, metadata)
    return archive, metadata_path


def private_env(root):
    env = {key: os.environ[key] for key in ("PATH", "GITHUB_ACTIONS", "RUNNER_ENVIRONMENT",
           "RUNNER_TEMP") if key in os.environ}
    env.update(LANG="C.UTF-8", HOME=str(root / "home"), USERPROFILE=str(root / "home"),
        XDG_DATA_HOME=str(root / "data"), XDG_CONFIG_HOME=str(root / "config"),
        XDG_CACHE_HOME=str(root / "cache"), XDG_RUNTIME_DIR=str(root / "runtime"),
        TMPDIR=str(root / "tmp"), RSRS_DATA_DIR=str(root / "installation"),
        RSRS_M3_DIR=str(root / "model"), RSRS_ENGINE="cpu", RSRS_NO_AUTOSYNC="1",
        RSRS_UPDATE_CHECK="0", RUST_MIN_STACK="16777216", RUST_TEST_THREADS="1")
    return env


def verify_receipt(root, metadata_path):
    metadata = json.loads(metadata_path.read_text())
    selected = json.loads((root / "runtime.json").read_text())
    runtime = root / "runtime" / metadata["runtime_version"] / "rsrs-runtime"
    require(selected.get("version") == metadata["runtime_version"]
            and selected.get("sha256") == metadata["binary_sha256"]
            and selected.get("release", {}).get("metadata_json") == metadata_path.read_text()
            and selected["release"]["metadata_sha256"] == digest(metadata_path)
            and digest(runtime) == metadata["binary_sha256"], "offline_receipt_mismatch")
    for entry in metadata["files"]:
        name = "rsrs-runtime" if entry["path"] == metadata["binary_file"] else entry["path"]
        path = safe_file(runtime.parent, name)
        require(path.stat().st_size == entry["size"] and digest(path) == entry["sha256"],
                "installed_inventory_mismatch")
    return runtime


def cleanup_processes(root, hashes):
    # Detached Runtime children do not necessarily remain in the test process group.
    # A unique inherited TMPDIR plus executable bytes binds only this run's children.
    marker = f"TMPDIR={root / 'tmp'}".encode()
    cleaned = 0
    for proc in Path("/proc").iterdir():
        if not proc.name.isdecimal():
            continue
        fd = None
        try:
            fd = os.pidfd_open(int(proc.name))
            if marker not in (proc / "environ").read_bytes().split(b"\0"):
                continue
            if digest(proc / "exe") not in hashes:
                continue
            signal.pidfd_send_signal(fd, signal.SIGKILL)
            cleaned += 1
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
        finally:
            if fd is not None:
                os.close(fd)
    return cleaned


def private_command(command, env, cwd, output, timeout):
    with subprocess.Popen([str(item) for item in command], env=env, cwd=cwd,
                          stdout=output, stderr=subprocess.STDOUT, start_new_session=True) as child:
        try:
            status = child.wait(timeout=timeout)
        except BaseException:
            # Do not leave the owned D-Bus/Secret Service group after interruption.
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait()
            raise
        require(status == 0, "private_command_failed")


def run(args):
    require(sys.platform == "linux" and platform.machine() == "x86_64"
            and os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted", "native_hosted_linux_required")
    root = args.root.resolve()
    temp = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    require(root.is_relative_to(temp) and root != temp and not root.exists(), "fresh_owned_root_required")
    os.umask(0o077)
    root.mkdir(mode=0o700)
    diagnostic = args.suite in ("diagnostic-failures", "diagnostic-native-stop")
    stable_remote = args.suite == "stable-diary-remote"
    report = {"schema_version": 1,
              "kind": "unpublished-source-diagnostic" if diagnostic else "unpublished-source-fixture",
              "case": ("native-stop-diagnostic" if args.suite == "diagnostic-native-stop" else
                       "targeted-failure-diagnostic" if diagnostic else
                       "stable-diary-remote-subset" if stable_remote else
                       CASE if args.suite == "account" else "full-business-suite"), "suite": args.suite,
              "client2_host_prototype": args.compatibility_host,
              "required_native_stop": args.require_native_stop,
              "passed": False, "release_acceptance": False, "test_executed": False,
              "cli_source_sha": args.cli_sha, "runtime_source_sha": args.runtime_sha,
              "run_id": os.environ.get("GITHUB_RUN_ID"), "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
              "target": TARGET, "stage": "source_identity"}
    env = private_env(root)
    for name in ("home", "data", "config", "cache", "runtime", "tmp", "installation"):
        (root / name).mkdir(mode=0o700)
    cli, runtime, harness = args.cli.resolve(), args.runtime.resolve(), args.harness.resolve()
    hashes = {digest(cli), digest(runtime), digest(harness)}
    log = root / "private.log"
    cases = []
    try:
        verify_source(args.cli_source, args.cli_sha)
        verify_source(args.runtime_source, args.runtime_sha)
        if stable_remote:
            diary_source = args.runtime_source / "crates/commands/examples/cli_business_tests/diary_identity.rs"
            fixture = diary_source.read_bytes()
            require(all(marker in fixture for marker in (
                b"RSRS_TEST_STABLE_DIARY_SUITE", b"RSRS_TEST_STABLE_CLI_BIN",
                b"fn business_command(", b"fn verify_business_owner(", b"fn business_output(")),
                "stable_business_fixture_support_missing")
            report["diary_source_sha256"] = digest(diary_source)
            stable_cli = args.stable_business_cli.resolve(strict=True)
            require(stable_cli not in (cli, runtime, harness), "stable_business_binary_not_separate")
            report["stable_business_cli"] = stable_business_identity(
                args.stable_business_cli, args.stable_business_cli_metadata,
                args.stable_business_runtime_archive, env)
            hashes.add(report["stable_business_cli"]["binary_sha256"])
            env.update(RSRS_TEST_STABLE_DIARY_SUITE="stable-diary-remote",
                       RSRS_TEST_STABLE_CLI_BIN=str(stable_cli))
        version = source_version(args.runtime_source, "runtime")
        cli_source_version = source_version(args.cli_source, "cli")
        cli_version = (official_cli_version(args.official_cli_metadata, cli, args.cli_sha, env)
                       if args.official_cli_metadata else cli_source_version)
        report.update(cli_source_version=cli_source_version,
                      cli_version_origin="official-release-metadata" if args.official_cli_metadata else "source-manifest")
        if args.official_cli_metadata:
            report["official_cli_metadata_sha256"] = digest(args.official_cli_metadata)
        pin = json.loads((args.cli_source / "runtime-pin.json").read_text())["required"]
        require(version != pin, "candidate_must_not_impersonate_official_pin")
        require((args.cli_source / "sdk/core-sdk.lock.json").read_bytes()
                == (args.runtime_source / "sdk/core-sdk.lock.json").read_bytes()
                == (args.runtime_source / "crates/core-sdk/core-sdk.lock.json").read_bytes(),
                "sdk_lock_mismatch")
        report.update(runtime_version=version, cli_version=cli_version,
            cli_binary_sha256=digest(cli), runtime_binary_sha256=digest(runtime),
            harness_sha256=digest(harness), sdk_lock_sha256=digest(args.runtime_source / "sdk/core-sdk.lock.json"),
            account_source_sha256=digest(args.runtime_source / "crates/commands/examples/cli_business_tests/account.rs"))
        report["stage"] = "candidate_archive"
        archive, metadata_path = package_runtime(runtime, runtime.parent, root / "archive",
            version, args.runtime_sha, args.cli_sha, digest(cli), cli_version)
        with log.open("wb") as output:
            def invoke(command, timeout=900):
                return private_command(command, env, args.cli_source, output, timeout)
            for binary, expected in ((cli, cli_version), (runtime, version)):
                actual = subprocess.check_output([str(binary), "--version"], env=env, timeout=30)
                require(expected.encode() in actual.split(), "compiled_version_mismatch")
            report["stage"] = "offline_install"
            invoke([cli, "--json", "runtime", "install", "--file", archive, "--version", version])
            installed = verify_receipt(root / "installation", metadata_path)
            report.update(runtime_archive_sha256=digest(archive), runtime_metadata_sha256=digest(metadata_path),
                          offline_installer_verified=True)
            report["stage"] = "real_model"
            invoke([cli, "--json", "model", "install-m3"], timeout=1800)
            sys.path.insert(0, str(args.cli_source / "scripts"))
            from dev_model_fixture import share_cpu_container
            share_cpu_container(root, env, root / "model")
            for name, expected in MODEL_HASHES.items():
                require(digest(safe_file(root / "model", name)) == expected, "real_model_digest_mismatch")
            report["model_sha256"] = MODEL_HASHES
            env.update(RSRS_CLI_BIN=str(cli), RSRS_CLI_SOURCE_DIR=str(args.cli_source.resolve()),
                RSRS_CLI_SOURCE_SHA=args.cli_sha, RSRS_RUNTIME_BIN=str(installed),
                RSRS_RUNTIME_SOURCE_SHA=args.runtime_sha, RSRS_RUNTIME_CANDIDATE_METADATA=str(metadata_path),
                RSRS_CORE_TEST_MODEL_DIR=str(root / "model"), RSRS_CORE_TEST_MODE="1")
            if args.compatibility_host:
                env["RSRS_TEST_EXPECT_CLIENT2_HOST"] = "1"
            listing = subprocess.check_output([str(harness), "--list"], env=env, timeout=30, stderr=output)
            listing_text = listing.decode()
            report["harness_case_count"] = sum(line.endswith(": test") for line in listing_text.splitlines())
            report["native_stop_present"] = f"{NATIVE_STOP_CASE}: test" in listing_text.splitlines()
            cases = selected_cases(listing_text, args.suite, args.require_native_stop)
            report["required_cases"] = cases
            report["selected_case_count"] = len(cases)
            test_args = ([*cases, "--exact", "--test-threads=1"]
                         if args.suite in ("account", "diagnostic-failures", "diagnostic-native-stop", "stable-diary-remote") else ["--test-threads=1"])
            if args.compatibility_host or diagnostic:
                test_args.append("--show-output")
            command = ["dbus-run-session", "--", "env", "RSRS_SS_FIXTURE_BUS=private",
                sys.executable, "-B", args.cli_source / "scripts/dev-secret-service-keyring-selftest.py",
                "--root", root / "keyring", "--", harness, *test_args]
            report["stage"] = "private_diagnostic_test" if diagnostic else "private_account_test"
            report["test_requested"] = True
            invoke(command, timeout=1000 if args.suite == "account" else 2700)
        report["stage"] = "result_verification"
        keyring = json.loads((root / "keyring/business-keyring-selftest.json").read_text())
        report["keyring"] = keyring
        require(keyring.get("passed") is True and keyring.get("business_passed") is True,
                "private_business_fixture_failed")
        require(digest(cli) == report["cli_binary_sha256"] and digest(runtime) == report["runtime_binary_sha256"]
                and digest(harness) == report["harness_sha256"], "executed_binaries_changed")
        if stable_remote:
            require(stable_business_identity(args.stable_business_cli, args.stable_business_cli_metadata,
                    args.stable_business_runtime_archive) == report["stable_business_cli"],
                    "stable_business_assets_changed")
        captured = log.read_bytes()
        require(f"test result: ok. {len(cases)} passed; 0 failed;".encode() in captured,
                "required_business_cases_did_not_pass")
        require(all(f"test {case} ... ok".encode() in captured.splitlines() for case in cases),
                "required_business_case_result_missing")
        if args.compatibility_host and args.suite != "diagnostic-native-stop":
            checks = compatibility_host_checks(captured)
            expected = {"import-target", "restart-target"}
            if args.suite in ("full", "diagnostic-failures"):
                expected.add("space-profile")
            require(checks is not None and checks and all(check["passed"] for check in checks)
                    and expected.issubset({check["stage"] for check in checks}),
                    "legacy_host_transitions_not_verified")
        report["stage"] = "complete"
        report["passed"] = True
    except Exception as error:
        # No raw exception text or command output: auth replies can contain secrets.
        report["failure_type"] = type(error).__name__
        if isinstance(error, RuntimeError) and re.fullmatch(r"[a-z_]+", str(error)):
            report["failure_code"] = str(error)
    finally:
        try:
            cleaned = cleanup_processes(root, hashes)
            time.sleep(0.1)
            require(cleanup_processes(root, hashes) == 0, "owned_process_cleanup_incomplete")
            report["owned_process_cleanup"] = {"passed": True, "forced": cleaned}
            if cleaned:
                report["passed"] = False
        except Exception:
            report["owned_process_cleanup"] = {"passed": False}
            report["passed"] = False
        if (root / "keyring/business-keyring-selftest.json").is_file():
            report["keyring"] = json.loads((root / "keyring/business-keyring-selftest.json").read_text())
        if log.is_file():
            captured = log.read_bytes()
            lines = captured.splitlines()
            if args.compatibility_host:
                report["compatibility_host_checks"] = compatibility_host_checks(captured)
            report["passed_cases"] = [case for case in cases if f"test {case} ... ok".encode() in lines]
            report["missing_or_failed_cases"] = [case for case in cases if case not in report["passed_cases"]]
            report["failure_diagnostics"] = safe_failure_diagnostics(captured, report["missing_or_failed_cases"])
            report["test_executed"] = bool(cases) and all(
                (f"test {case} ... ".encode() in captured) for case in cases)
        report["passed"] = report["passed"] and report["test_executed"]
        write_json(root / "result.json", report)
    print(json.dumps({"case": report["case"], "passed": report["passed"], "test_executed": report["test_executed"]}))
    return 0 if report["passed"] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("root", "cli-source", "runtime-source", "cli", "runtime", "harness"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--cli-sha", required=True)
    parser.add_argument("--runtime-sha", required=True)
    parser.add_argument("--suite", choices=("account", "full", "diagnostic-failures", "diagnostic-native-stop", "stable-diary-remote"), default="account")
    parser.add_argument("--compatibility-host", action="store_true")
    parser.add_argument("--require-native-stop", action="store_true")
    parser.add_argument("--official-cli-metadata", type=Path,
                        help="Verified fixed official dev.6 GNU sidecar; preserves its release version")
    for name in ("stable-business-cli", "stable-business-cli-metadata", "stable-business-runtime-archive"):
        parser.add_argument("--" + name, type=Path)
    def interrupted(_number, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    args = parser.parse_args()
    if args.require_native_stop and args.suite != "full":
        parser.error("--require-native-stop requires --suite full")
    stable_paths = (args.stable_business_cli, args.stable_business_cli_metadata,
                    args.stable_business_runtime_archive)
    if args.suite == "stable-diary-remote":
        if (not all(stable_paths) or args.official_cli_metadata or args.compatibility_host
                or args.require_native_stop):
            parser.error("stable-diary-remote requires three stable assets and the current manager without compatibility/native-stop")
    elif any(stable_paths):
        parser.error("stable business assets require --suite stable-diary-remote")
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
