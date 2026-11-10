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
G1_BUSINESS_CASES = (
    "diary_identity::remember_public_payload_covers_created_appended_and_merged",
    "diary_identity::concurrent_same_day_client_commands_preserve_each_successful_addition_once",
)
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
    if suite == "g1-business":
        require(all(names.count(case) == 1 for case in G1_BUSINESS_CASES),
                "g1_business_case_inventory_mismatch")
        return list(G1_BUSINESS_CASES)
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

def stable_legacy_probe_checks(captured):
    # This marker proves a harness probe's legacy projection, not its sender
    # being the old CLI. The separately verified binary executes business calls.
    marker = b"stable-diary-legacy-probe "
    expected = {"probe_without_scope": True, "legacy_projection_verified": True,
                "same_actor_before_after": True, "candidate_process_verified": True}
    checks = []
    for line in captured.splitlines():
        if marker not in line:
            continue
        try:
            value = json.loads(line.split(marker, 1)[1])
        except (ValueError, UnicodeDecodeError):
            return None
        if (not isinstance(value, dict) or set(value) != set(expected)
                or any(value[key] is not True for key in expected) or len(checks) >= 128):
            return None
        checks.append(expected.copy())
    return checks


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
        b'registered lifecycle command failed with exit code': 'owned_registered_lifecycle_failed',
        b'registered service could not unlock its actual persistent credential': 'owned_registered_unlock_failed',
        b'original Go Manager.Start failed': 'owned_client2_start_failed',
        b'original Go startup/RPC failed': 'owned_client2_start_rpc_failed',
        b'registered business did not reach the actual provider': 'owned_registered_provider_not_reached',
        b'actual Client2-owned SDK callback missing': 'owned_client2_provider_not_reached',
        b'library lock check failed without proving contention': 'owned_library_lock_unproved',
        b'owned Runtime released its library lock before business cleanup': 'owned_library_lock_released_early',
        b'REGISTERED_STOP_CLEANUP_FAILED': 'owned_registered_cleanup_preserved',
        b'CLIENT2_OWNED_STOP_CLEANUP_FAILED': 'owned_client2_cleanup_preserved',
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
        b"auth maintenance profile differs from the selected profile": "auth_maintenance_profile_mismatch",
        b"auth maintenance installation changed": "auth_maintenance_installation_changed",
        b"auth maintenance marker is missing": "auth_maintenance_marker_missing",
        b"auth maintenance ownership is missing": "auth_maintenance_owner_missing",
        b"auth maintenance digest is missing": "auth_maintenance_digest_missing",
        b"auth maintenance owner or phase changed": "auth_maintenance_owner_phase_changed",
        b"auth control requires this installation's takeover ownership": "auth_control_takeover_mismatch",
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
        b"runtime restart blocked: owner roots do not match this installation": "runtime_stop_root_mismatch",
        b"runtime process already exited": "runtime_stop_owner_already_exited",
        b"runtime drain stop request failed": "runtime_drain_stop_request_failed",
        b"runtime drain final receipt verification failed": "runtime_drain_final_receipt_failed",
        b"runtime drain listener did not close": "runtime_drain_listener_close_failed",
        b"runtime drain endpoint removal failed": "runtime_drain_endpoint_remove_failed",
        b"runtime stop host policy rejected": "runtime_stop_host_policy_rejected",
        b"runtime stop HTTP exchange failed": "runtime_stop_http_exchange_failed",
        b"runtime_unavailable:": "runtime_error_unavailable",
        b"runtime_token_unreadable:": "runtime_error_token_unreadable",
        b"runtime_unauthorized:": "runtime_error_unauthorized",
        b"runtime_transport:": "runtime_error_transport",
        b"runtime stop identity is incomplete": "runtime_stop_identity_incomplete",
        b"invalid stop acknowledgement": "runtime_stop_ack_invalid_json",
        b"runtime did not accept a traceable stop operation": "runtime_stop_ack_untraceable",
        b"stop acknowledgement lacks operation ID": "runtime_stop_ack_operation_missing",
        b"final runtime stop receipt is missing": "runtime_stop_final_receipt_missing",
        b"invalid runtime stop instance ID": "runtime_stop_instance_invalid",
        b"stopped runtime belongs to another installation": "runtime_stop_receipt_installation_mismatch",
        b"invalid stop receipt file": "runtime_stop_receipt_file_invalid",
        b"stop receipt exceeds 1 MiB": "runtime_stop_receipt_file_too_large",
        b"invalid final stop receipt": "runtime_stop_receipt_json_invalid",
        b"runtime stopped without a proven complete drain": "runtime_stop_drain_unproven",
        b"runtime did not exit after stop": "runtime_stop_listener_still_open",
        b"manual snapshot owner differs from the installed Runtime": "snapshot_manual_owner_identity_mismatch",
        b"manual snapshot owner exited before drain": "snapshot_manual_owner_already_exited",
        b"snapshot marker already bound; query that operation instead of draining again": "snapshot_marker_already_bound",
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
    snapshot_stages = []
    stage_invalid = False
    allowed_stages = {"candidate_guard", "remote_create", "remote_list", "old_install", "old_start",
                      "old_create", "old_update", "old_restart", "old_restore", "old_recovery", "old_cleanup"}
    for case in failed_cases:
        for line in blocks.get(case, []):
            if not line.startswith(b"legacy-snapshot-stage "):
                continue
            try:
                if len(line) > 2048 or len(snapshot_stages) >= 64:
                    raise ValueError
                event = json.loads(line[len(b"legacy-snapshot-stage "):])
                if (not isinstance(event, dict) or set(event) != {"case", "stage"}
                        or event["case"] != case or event["stage"] not in allowed_stages):
                    raise ValueError
                snapshot_stages.append(event)
            except (ValueError, TypeError):
                stage_invalid = True
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
        codes[case] = list(dict.fromkeys(code for text, code in known.items() if text in block))
        # HTTP details can contain URLs and response data. Retain only a fixed
        # status when the same line identifies this failed stop exchange.
        for line in blocks.get(case, []):
            if (b"runtime stop HTTP exchange failed" not in line
                    or b"runtime_transport:" not in line or len(line) > 65536):
                continue
            for status in (b"400", b"401", b"403", b"404", b"409", b"429", b"500", b"502", b"503", b"504"):
                if re.search(rb"(?:status code |unexpected HTTP )" + status + rb"(?![0-9])", line):
                    code = "runtime_stop_http_" + status.decode("ascii")
                    if code not in codes[case]:
                        codes[case].append(code)
        if not codes[case]:
            codes[case] = ["unknown_private_failure"]
        locations[case] = []
        for line in blocks.get(case, []):
            if b"panicked at " not in line or len(line) > 8192:
                continue
            for match in re.finditer(rb"[/\\](account\.rs|snapshot_lifecycle\.rs|diary_identity\.rs|capture_main\.rs|memory_revision\.rs):([0-9]{1,6}):([0-9]{1,4}):", line):
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
    owned_checkpoints, owned_invalid, owned_seen = [], False, 0
    owned_stages = {"actors_bound", "actors_exited", "bundle_staged", "business_completed", "caller_wait_complete", "cleanup_complete", "cleanup_requested", "complete", "core_bound", "core_reaped", "credential_ready", "credential_requested", "drain_observed", "fixture_created", "fixture_ready", "force_requested", "health_bound", "lock_held_draining", "lock_held_initial", "memory_seeded", "provider_finished", "provider_received", "provider_release_requested", "provider_requested", "quiet_period_verified", "receipt_verified", "recovery_bound", "recovery_requested", "recovery_started", "recovery_stop_requested", "recovery_stopped", "runtime_install_requested", "runtime_installed", "start", "start_complete", "start_requested", "stop_requested", "stop_started", "write_verified"}
    marker = b"OWNED_STOP_CHECKPOINT "
    for line in blocks.get(NATIVE_STOP_CASE, []):
        if b"OWNED_STOP_CHECKPOINT" not in line:
            continue
        owned_seen += 1
        if owned_seen > 128:
            owned_invalid = True
            break
        try:
            if not line.startswith(marker) or len(line) > 2048:
                raise ValueError
            event = json.loads(line[len(marker):])
            if (not isinstance(event, dict) or set(event) != {"startup_mode", "case", "stage"}
                    or not all(isinstance(value, str) for value in event.values())
                    or event["startup_mode"] not in {"registered", "client2-owned"}
                    or event["case"] not in {"normal", "caller-timeout", "explicit-force"}
                    or event["stage"] not in owned_stages):
                raise ValueError
            owned_checkpoints.append(event)
        except (ValueError, TypeError):
            owned_invalid = True
    return {"authorization_events": events, "authorization_event_invalid": invalid,
            "failure_codes": codes, "failure_locations": locations,
            "legacy_snapshot_stages": snapshot_stages, "legacy_snapshot_stage_invalid": stage_invalid,
            "response_events": response_events, "response_event_invalid": response_invalid,
            "native_stop_checkpoints": checkpoints, "native_stop_checkpoint_invalid": checkpoint_invalid,
            "owned_stop_checkpoints": owned_checkpoints, "owned_stop_checkpoint_invalid": owned_invalid}


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


def stable_business_identity(cli, metadata_path, archive, env=None, *, full_contracts=False):
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
            core_bytes = core_stream.read()
            core = json.loads(core_bytes)
        if full_contracts:
            require(safe_file(cli.parent, "core-runtime.json").read_bytes() == core_bytes,
                    "stable_staged_core_metadata_changed")
            require(isinstance(core.get("files"), list), "stable_staged_core_inventory_missing")
            for row in core["files"]:
                require(isinstance(row, dict) and isinstance(row.get("path"), str)
                        and row["path"].startswith("core-notices/")
                        and re.fullmatch(r"[0-9a-f]{64}", row.get("sha256", "")),
                        "stable_staged_notice_identity_invalid")
                require(digest(safe_file(cli.parent, row["path"])) == row["sha256"],
                        "stable_staged_notice_changed")
        require(core.get("schema_version") == 1 and core.get("target") == TARGET,
                "stable_business_core_identity_mismatch")
    if env is not None:
        actual = subprocess.check_output([str(cli), "--version"], env=env,
                                         stderr=subprocess.PIPE, timeout=30)
        require(b"1.0.20" in actual.split(), "stable_business_version_mismatch")
    return {"version": "1.0.20", "source_sha": expected["git_sha"], "target": TARGET,
            "binary_sha256": digest(cli), "metadata_sha256": digest(metadata_path),
            "runtime_archive_sha256": digest(archive),
            "scope": ("fixed_existing_stable_contracts_in_full31_not_all_product_features" if full_contracts
                      else "ten_remote_diary_cases_not_all_stable_features"),
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


def frozen_runtime_package(args, runtime, version):
    # Keep exact compressed candidate bytes. The existing installer/receipt
    # checks validate archive members and every installed payload byte.
    archive = args.runtime_archive.resolve(strict=True)
    metadata_path = args.runtime_metadata.resolve(strict=True)
    require(archive.is_file() and metadata_path.is_file()
            and not args.runtime_archive.is_symlink() and not args.runtime_metadata.is_symlink(),
            "frozen_runtime_files_required")
    metadata = json.loads(metadata_path.read_text())
    require(metadata.get("schema_version") == 2 and metadata.get("target_triple") == TARGET
            and metadata.get("runtime_version") == version
            and metadata.get("source_commit") == args.runtime_sha
            and metadata.get("archive_file") == archive.name
            and metadata.get("archive_sha256") == digest(archive)
            and metadata.get("binary_sha256") == digest(runtime)
            and metadata.get("candidate") == {
                "kind": "unpublished-source-fixture", "cli_source_sha": args.cli_sha,
                "cli_binary_sha256": digest(args.cli.resolve(strict=True))},
            "frozen_runtime_identity_mismatch")
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


def cleanup_processes(root, hashes, observations=None):
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
            image_sha256 = digest(proc / "exe")
            if image_sha256 not in hashes:
                continue
            signal.pidfd_send_signal(fd, signal.SIGKILL)
            cleaned += 1
            if observations is not None:
                # Only existing run-bound executable hashes and a numeric PID.
                # Never retain environ, command lines, paths or exception text.
                observations.append({"pid": int(proc.name), "image_sha256": image_sha256})
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
        finally:
            if fd is not None:
                os.close(fd)
    return cleaned


CLIENT2_OWNED_SOURCE_SHA = "57bc070826949994c3f7ce9a64277160704bdfe5"
OWNED_PROBE_FILES = ("diagnostics_darwin.go", "diagnostics_other.go", "host_operations.go", "main.go")


def validate_owned_stop_options(args):
    if args.owned_stop_mode is None:
        require(args.client2_source is None, "owned_stop_source_requires_mode")
        return
    require(args.owned_stop_mode in ("registered", "client2-owned"), "unknown_owned_stop_mode")
    require(args.suite == "diagnostic-native-stop" and args.client2_source is not None
            and not args.official_cli_metadata and not args.legacy_stable_contracts
            and not any((args.stable_business_cli, args.stable_business_cli_metadata,
                         args.stable_business_runtime_archive))
            and not args.runtime_archive and not args.runtime_metadata
            and not args.require_native_stop, "owned_stop_requires_current_candidate_diagnostic")
    require(args.cli_sha == os.environ.get("GITHUB_SHA") and re.fullmatch(r"[a-f0-9]{40}", args.cli_sha)
            and re.fullmatch(r"[a-f0-9]{40}", args.runtime_sha), "owned_stop_workflow_source_mismatch")


def build_owned_stop_probe(args, root, output):
    # Never accept an external executable: derive the probe from both exact Git sources.
    validate_owned_stop_options(args)
    source = args.client2_source.resolve(strict=True)
    verify_source(source, CLIENT2_OWNED_SOURCE_SHA)
    stage = root / "owned-stop-probe"
    stage.mkdir(mode=0o700)
    archive = stage / "client2-source.tar"
    with archive.open("wb") as stream:
        subprocess.run(["git", "-C", str(source), "archive", "--format=tar", CLIENT2_OWNED_SOURCE_SHA],
                       stdout=stream, stderr=output, check=True, timeout=60)
    extracted = stage / "client2"
    extracted.mkdir()
    with tarfile.open(archive) as stream:
        members = stream.getmembers()
        require(len(members) < 10000 and sum(row.size for row in members) < 256 * 1024 * 1024
                and all((row.isfile() or row.isdir()) and not Path(row.name).is_absolute()
                        and ".." not in Path(row.name).parts and "\\" not in row.name
                        for row in members), "owned_stop_source_archive_rejected")
        stream.extractall(extracted, filter="data")
    probe = stage / "probe"
    probe.mkdir()
    fixture_hashes = {}
    for name in OWNED_PROBE_FILES:
        tracked = "scripts/fixtures/client2-v0256-probe/" + name
        content = subprocess.check_output(["git", "-C", str(args.cli_source), "show", args.cli_sha + ":" + tracked])
        require(content == (args.cli_source / tracked).read_bytes(), "owned_stop_probe_fixture_changed")
        (probe / name).write_bytes(content)
        fixture_hashes[tracked] = hashlib.sha256(content).hexdigest()
    (probe / "go.mod").write_text("module respire-client2/regression\n\ngo 1.26.0\n\n"
        "require respire-client2 v0.0.0\nreplace respire-client2 => " + json.dumps(str(extracted)) + "\n")
    (probe / "go.sum").write_bytes((extracted / "go.sum").read_bytes())
    build_env = {name: os.environ[name] for name in ("PATH", "SystemRoot", "WINDIR") if name in os.environ}
    build_env.update(GOPATH=str(stage / "go-path"), GOCACHE=str(stage / "go-cache"),
                     GOMODCACHE=str(stage / "go-mod"), GOTOOLCHAIN="local", GOENV="off", GOWORK="off")
    binary = probe / "probe"
    subprocess.run(["go", "build", "-buildvcs=false", "-mod=mod", "-o", str(binary), "."],
                   cwd=probe, env=build_env, stdout=output, stderr=output, check=True, timeout=600)
    require(binary.is_file() and not binary.is_symlink(), "owned_stop_probe_binary_missing")
    identity = {"client2_source_sha": CLIENT2_OWNED_SOURCE_SHA,
        "client2_source_archive_sha256": digest(archive), "probe_fixture_cli_sha": args.cli_sha,
        "probe_fixture_sha256": fixture_hashes, "generated_go_mod_sha256": digest(probe / "go.mod"),
        "source_go_sum_sha256": digest(extracted / "go.sum"), "resolved_go_sum_sha256": digest(probe / "go.sum"),
        "probe_binary_sha256": digest(binary), "mode": args.owned_stop_mode,
        "workflow_source_sha": os.environ.get("GITHUB_SHA"), "run_id": os.environ.get("GITHUB_RUN_ID"),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT")}
    return binary, identity


def owned_stop_checks(captured, mode, probe_sha256, runtime_sha256):
    marker = b"NATIVE_REGISTERED_STOP_RAW " if mode == "registered" else b"NATIVE_CLIENT2_STOP_RAW "
    rows = [json.loads(line.split(marker, 1)[1]) for line in captured.splitlines() if marker in line]
    require(len(rows) == 3 and {row["case"] for row in rows} == {"normal", "caller-timeout", "explicit-force"},
            "owned_stop_case_inventory_mismatch")
    expected_mode = "cli-supervised" if mode == "registered" else "client2-owned"
    for row in rows:
        require(row.get("startup_mode") == expected_mode and row.get("passed") is True
                and row.get("probe_sha256") == probe_sha256 and row.get("business_sender") == "modern-harness"
                and row.get("provider_http_status") == 200 and row.get("provider_requests") == 1
                and row.get("credential_cleanup_verified") is True
                and row.get("runtime_compatibility_timeout_claimed") is False
                and row["runtime_identity"]["image_sha256"] == runtime_sha256,
                "owned_stop_real_consumer_evidence_mismatch")
        expected_sender = ("modern-cli" if row["case"] == "normal" else "original-go-client2-managed") if mode == "registered" else "original-go-client2"
        require(row.get("stop_sender") == expected_sender, "owned_stop_sender_mismatch")
        timeout = row.get("caller_timeout_ms")
        require(timeout is None if row["case"] == "normal" else
                type(timeout) is int and (35000 if mode == "registered" else 30000) <= timeout <= 60000,
                "owned_stop_caller_timeout_invalid")
        forced = row["case"] == "explicit-force"
        require(row.get("encrypted_write_committed") is (not forced)
                and row.get("forced_operation_remains_unknown") is forced,
                "owned_stop_write_outcome_mismatch")
    # Only source-defined scalar observations leave the private business log.
    return [{key: row.get(key) for key in ("case", "startup_mode", "business_sender", "stop_sender",
        "caller_timeout_ms", "provider_http_status", "provider_requests", "encrypted_write_committed",
        "forced_operation_remains_unknown", "credential_cleanup_verified")} for row in rows]


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
    stable_full = args.legacy_stable_contracts
    report = {"schema_version": 1,
              "kind": "unpublished-source-diagnostic" if diagnostic else "unpublished-source-fixture",
              "case": ("native-stop-diagnostic" if args.suite == "diagnostic-native-stop" else
                       "targeted-failure-diagnostic" if diagnostic else
                       "stable-diary-remote-subset" if stable_remote else
                       "g1-business-subset" if args.suite == "g1-business" else
                       CASE if args.suite == "account" else "full-business-suite"), "suite": args.suite,
              "client2_host_prototype": args.compatibility_host,
              "required_native_stop": args.require_native_stop,
              "passed": False, "release_acceptance": False, "test_executed": False,
              "cli_source_sha": args.cli_sha, "runtime_source_sha": args.runtime_sha,
              "run_id": os.environ.get("GITHUB_RUN_ID"), "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
              "target": TARGET, "stage": "source_identity"}
    validate_owned_stop_options(args)
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
        if stable_remote or stable_full:
            diary_source = args.runtime_source / "crates/commands/examples/cli_business_tests/diary_identity.rs"
            fixture = diary_source.read_bytes()
            require(all(marker in fixture for marker in (
                b"RSRS_TEST_STABLE_DIARY_SUITE", b"RSRS_TEST_STABLE_CLI_BIN",
                b"fn business_command(", b"fn verify_business_owner(", b"fn business_output(",
                b"fn verify_legacy_projection(", b"stable-diary-legacy-probe ")),
                "stable_business_fixture_support_missing")
            report["diary_source_sha256"] = digest(diary_source)
            stable_cli = args.stable_business_cli.resolve(strict=True)
            require(stable_cli not in (cli, runtime, harness), "stable_business_binary_not_separate")
            report["stable_business_cli"] = stable_business_identity(
                args.stable_business_cli, args.stable_business_cli_metadata,
                args.stable_business_runtime_archive, env, full_contracts=stable_full)
            hashes.add(report["stable_business_cli"]["binary_sha256"])
            if stable_remote:
                env.update(RSRS_TEST_STABLE_DIARY_SUITE="stable-diary-remote",
                           RSRS_TEST_STABLE_CLI_BIN=str(stable_cli))
            if stable_full:
                report["legacy_contracts"] = {"passed":False,
                    "scope":"existing_stable_contracts_in_full31_not_all_product_features",
                    "current_full31_is_separate":True,"modern_only":[NATIVE_STOP_CASE,
                        "runtime.account-result","runtime.account-rollback","scoped_http_fingerprint_matrix"],
                    "required_cases":list(BASELINE_CASES),"executed_cases":[],"missing_cases":list(BASELINE_CASES)}
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
        if args.suite == "g1-business":
            archive, metadata_path = frozen_runtime_package(args, runtime, version)
        else:
            archive, metadata_path = package_runtime(runtime, runtime.parent, root / "archive",
                version, args.runtime_sha, args.cli_sha, digest(cli), cli_version)
        with log.open("wb") as output:
            def invoke(command, timeout=900):
                return private_command(command, env, args.cli_source, output, timeout)
            if args.owned_stop_mode:
                probe, probe_identity = build_owned_stop_probe(args, root, output)
                report["owned_stop"] = {"source_binding": probe_identity, "passed": False}
                hashes.add(probe_identity["probe_binary_sha256"])
                env.update(RSRS_TEST_NATIVE_OWNED_STOP=args.owned_stop_mode, RSRS_CLIENT2_PROBE_BIN=str(probe))
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
                         if args.suite in ("account", "g1-business", "diagnostic-failures", "diagnostic-native-stop", "stable-diary-remote") else ["--test-threads=1"])
            if args.compatibility_host or diagnostic or stable_remote:
                test_args.append("--show-output")
            command = ["dbus-run-session", "--", "env", "RSRS_SS_FIXTURE_BUS=private",
                sys.executable, "-B", args.cli_source / "scripts/dev-secret-service-keyring-selftest.py",
                "--root", root / "keyring", "--", harness, *test_args]
            report["stage"] = "private_diagnostic_test" if diagnostic else "private_account_test"
            report["test_requested"] = True
            invoke(command, timeout=1000 if args.suite == "account" else 2700)
            if stable_full:
                # Separate output and private keyring prevent the second pass from
                # satisfying any original current31 result or credential assertion.
                legacy_cases = list(BASELINE_CASES)
                legacy_env = dict(env, RSRS_TEST_LEGACY_STABLE_CONTRACTS="stable-contracts-v1",
                    RSRS_TEST_STABLE_DIARY_SUITE="stable-diary-remote",
                    RSRS_TEST_STABLE_CLI_BIN=str(stable_cli))
                legacy_log = root / "legacy-private.log"
                legacy_command = ["dbus-run-session", "--", "env", "RSRS_SS_FIXTURE_BUS=private",
                    sys.executable, "-B", args.cli_source / "scripts/dev-secret-service-keyring-selftest.py",
                    "--root", root / "legacy-keyring", "--", harness, *legacy_cases,
                    "--exact", "--test-threads=1", "--show-output"]
                with legacy_log.open("wb") as private_output:
                    private_command(legacy_command, legacy_env, args.cli_source, private_output, 2700)
                legacy_keyring = json.loads((root / "legacy-keyring/business-keyring-selftest.json").read_text())
                require(legacy_keyring.get("passed") is True and legacy_keyring.get("business_passed") is True,
                        "legacy_private_business_fixture_failed")
                legacy_output = legacy_log.read_bytes()
                roles = {"diary_identity":"candidate_runtime", "memory_revision":"old_embedded",
                         "capture_main":"host_local", "account":"old_embedded",
                         "snapshot_lifecycle":"old_embedded"}
                receipts = []
                for line in legacy_output.splitlines():
                    if b"legacy-stable-contract " not in line:
                        continue
                    value = json.loads(line.split(b"legacy-stable-contract ", 1)[1])
                    require(isinstance(value, dict) and set(value) == {"case","sender","execution","passed"}
                            and value["case"] in legacy_cases and value["sender"] == "old_cli"
                            and value["execution"] == roles[value["case"].split("::")[0]]
                            and value["passed"] is True and len(receipts) < 30,
                            "legacy_contract_receipt_invalid")
                    receipts.append(value)
                executed = [value["case"] for value in receipts]
                require(len(executed) == len(set(executed)) == len(legacy_cases)
                        and set(executed) == set(legacy_cases)
                        and all(f"test {case} ... ok".encode() in legacy_output.splitlines() for case in legacy_cases),
                        "legacy_contract_case_result_missing")
                api_features = {"snapshot.create", "snapshot.list", "witness.verify", "feedback.mark", "recall.empty"}
                observed_apis = []
                for line in legacy_output.splitlines():
                    if b"legacy-stable-api " not in line:
                        continue
                    value = json.loads(line.split(b"legacy-stable-api ", 1)[1])
                    require(isinstance(value, dict) and set(value) == {"feature","sender","execution","passed"}
                            and value["feature"] in api_features and value["sender"] == "old_cli"
                            and value["execution"] == "candidate_runtime" and value["passed"] is True
                            and len(observed_apis) < 64, "legacy_remote_api_receipt_invalid")
                    observed_apis.append(value)
                require({value["feature"] for value in observed_apis} == api_features,
                        "legacy_remote_api_contract_missing")
                report["legacy_contracts"]["recovery_input_origin"] = "harness_original_schema_with_old_snapshot_bytes"
                report["legacy_contracts"]["recovery_interruption_by_old_binary"] = False
                report["legacy_contracts"]["candidate_api_receipts"] = observed_apis
                report["legacy_contracts"]["modern_substeps_not_claimed_as_old"] = [
                    "snapshot_staged_store_fault_injection", "queued_direct_rpc_resume",
                    "scoped_idempotency_matrix", "account_awaiting_input_result_and_rollback"]
                missing = [case for case in BASELINE_CASES if case not in executed]
                report["legacy_contracts"].update(executed_cases=executed, missing_cases=missing,
                    receipts=receipts, keyring=legacy_keyring, passed=not missing)
                require(not missing, "legacy_contract_case_missing")
        report["stage"] = "result_verification"
        keyring = json.loads((root / "keyring/business-keyring-selftest.json").read_text())
        report["keyring"] = keyring
        require(keyring.get("passed") is True and keyring.get("business_passed") is True,
                "private_business_fixture_failed")
        require(digest(cli) == report["cli_binary_sha256"] and digest(runtime) == report["runtime_binary_sha256"]
                and digest(harness) == report["harness_sha256"], "executed_binaries_changed")
        if stable_remote or stable_full:
            require(stable_business_identity(args.stable_business_cli, args.stable_business_cli_metadata,
                    args.stable_business_runtime_archive, full_contracts=stable_full) == report["stable_business_cli"],
                    "stable_business_assets_changed")
        captured = log.read_bytes()
        require(f"test result: ok. {len(cases)} passed; 0 failed;".encode() in captured,
                "required_business_cases_did_not_pass")
        require(all(f"test {case} ... ok".encode() in captured.splitlines() for case in cases),
                "required_business_case_result_missing")
        if stable_remote:
            probes = stable_legacy_probe_checks(captured)
            require(probes is not None and len(probes) >= len(cases),
                    "stable_legacy_projection_not_verified")
        if args.compatibility_host and args.suite != "diagnostic-native-stop":
            checks = compatibility_host_checks(captured)
            expected = {"import-target", "restart-target"}
            if args.suite in ("full", "diagnostic-failures"):
                expected.add("space-profile")
            require(checks is not None and checks and all(check["passed"] for check in checks)
                    and expected.issubset({check["stage"] for check in checks}),
                    "legacy_host_transitions_not_verified")
        if args.owned_stop_mode:
            require(digest(probe) == probe_identity["probe_binary_sha256"], "owned_stop_probe_binary_changed")
            report["owned_stop"]["observations"] = owned_stop_checks(captured, args.owned_stop_mode,
                probe_identity["probe_binary_sha256"], report["runtime_binary_sha256"])
            report["owned_stop"].update(passed=True, runtime_archive_sha256=report["runtime_archive_sha256"],
                runtime_metadata_sha256=report["runtime_metadata_sha256"], runtime_source_sha=args.runtime_sha,
                cli_source_sha=args.cli_sha, harness_sha256=report["harness_sha256"])
        report["stage"] = "complete"
        report["passed"] = True
    except Exception as error:
        # No raw exception text or command output: auth replies can contain secrets.
        report["failure_type"] = type(error).__name__
        if isinstance(error, RuntimeError) and re.fullmatch(r"[a-z_]+", str(error)):
            report["failure_code"] = str(error)
    finally:
        try:
            forced_processes = []
            cleaned = cleanup_processes(root, hashes, forced_processes)
            time.sleep(0.1)
            require(cleanup_processes(root, hashes) == 0, "owned_process_cleanup_incomplete")
            roles = {report.get("cli_binary_sha256"): "current_cli",
                     report.get("runtime_binary_sha256"): "candidate_runtime",
                     report.get("harness_sha256"): "harness",
                     report.get("owned_stop", {}).get("source_binding", {}).get("probe_binary_sha256"): "original_client2_probe",
                     report.get("stable_business_cli", {}).get("binary_sha256"): "official_stable_cli"}
            for process in forced_processes:
                process["image_role"] = roles.get(process["image_sha256"], "run_bound_unknown")
            report["owned_process_cleanup"] = {"passed": True, "forced": cleaned,
                                                "forced_processes": forced_processes}
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
            if stable_full:
                legacy_keyring_path = root / "legacy-keyring/business-keyring-selftest.json"
                if legacy_keyring_path.is_file():
                    report["legacy_contracts"]["keyring"] = json.loads(legacy_keyring_path.read_text())
                report["legacy_contracts"]["current_full31_passed"] = (
                    len(cases) == 31 and all(f"test {case} ... ok".encode() in lines for case in cases)
                    and b"test result: ok. 31 passed; 0 failed;" in captured)
                legacy_log = root / "legacy-private.log"
                if legacy_log.is_file():
                    private = legacy_log.read_bytes()
                    passed = [case for case in BASELINE_CASES if f"test {case} ... ok".encode() in private.splitlines()]
                    failed = [case for case in BASELINE_CASES if case not in passed]
                    report["legacy_contracts"].update(passed_cases=passed, missing_or_failed_cases=failed,
                        failure_diagnostics=safe_failure_diagnostics(private, failed))
            if stable_remote:
                report["stable_legacy_probe_checks"] = stable_legacy_probe_checks(captured)
                report["stable_legacy_probe_scope"] = "harness_probe_only_not_old_binary_sender"
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
    parser.add_argument("--suite", choices=("account", "full", "g1-business", "diagnostic-failures", "diagnostic-native-stop", "stable-diary-remote"), default="account")
    parser.add_argument("--runtime-archive", type=Path)
    parser.add_argument("--runtime-metadata", type=Path)
    parser.add_argument("--owned-stop-mode", choices=("registered", "client2-owned"))
    parser.add_argument("--client2-source", type=Path)
    parser.add_argument("--legacy-stable-contracts", action="store_true")
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
    if args.suite == "g1-business":
        if (not args.runtime_archive or not args.runtime_metadata or args.compatibility_host
                or args.official_cli_metadata or args.require_native_stop or args.legacy_stable_contracts):
            parser.error("g1-business requires frozen Runtime archive/metadata and current CLI without compatibility/native-stop/stable-contracts")
    elif args.runtime_archive or args.runtime_metadata:
        parser.error("frozen Runtime inputs require --suite g1-business")
    if args.require_native_stop and args.suite != "full":
        parser.error("--require-native-stop requires --suite full")
    stable_paths = (args.stable_business_cli, args.stable_business_cli_metadata,
                    args.stable_business_runtime_archive)
    if args.legacy_stable_contracts:
        if (args.suite != "full" or not all(stable_paths) or args.official_cli_metadata
                or args.compatibility_host or not args.require_native_stop):
            parser.error("legacy stable contracts require full31, three fixed stable assets and the current manager")
    elif args.suite == "stable-diary-remote":
        if (not all(stable_paths) or args.official_cli_metadata or args.compatibility_host
                or args.require_native_stop):
            parser.error("stable-diary-remote requires three stable assets and the current manager without compatibility/native-stop")
    elif any(stable_paths):
        parser.error("stable business assets require --suite stable-diary-remote")
    validate_owned_stop_options(args)
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
