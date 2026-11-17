#!/usr/bin/env python3
"""Verify actual Secret Service migration observations for an exact CI artifact."""
import argparse
import json
from pathlib import Path
import re
import sys


REQUIRED = {"model_cpu_real", "onememory_multiaccount_wal_migrated",
    "respire_compatibility_migrated", "legacy_db_with_explicit_current_credentials",
    "explicit_dev_endpoint_preserved", "migration_repeated_start_idempotent",
    "migration_interrupted_restart_recovered", "existing_rsrs_preserved_and_legacy_imported",
    "migrated_outbox_sync_and_independent_decrypt", "migration_wrong_key_rejected", "migration_incompatible_primary_keys_rejected",
    "migration_symlink_root_rejected", "migration_client_only_does_not_write",
    "secret_service_current_credentials_for_legacy_db", "startup_does_not_migrate",
    "migration_source_order_and_backup_only_idempotent",
    "restart_locked_with_native_credentials_then_host_unlock"}


def require(value, code):
    if not value:
        raise RuntimeError(code)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ("migration-report", "report"):
        parser.add_argument("--" + field, type=Path, required=True)
    for field in ("source-sha", "binary-sha256", "version"):
        parser.add_argument("--" + field, required=True)
    args = parser.parse_args()
    result = {"passed": False, "source_sha": args.source_sha,
        "binary_sha256": args.binary_sha256, "version": args.version,
        "scope": "Native Secret Service migration; separate from kernel fallback coverage."}
    try:
        require(re.fullmatch("[0-9a-f]{40}", args.source_sha)
            and re.fullmatch("[0-9a-f]{64}", args.binary_sha256), "artifact_identity_invalid")
        report = json.loads(args.migration_report.read_text(encoding="utf-8"))
        require(all(report.get(key) == value for key, value in
            (("source_sha", args.source_sha), ("binary_sha256", args.binary_sha256),
             ("version", args.version))), "secret_service_artifact_identity_mismatch")
        require(report.get("platform") == "linux"
            and report.get("keyring_backend") == "linux-secret-service", "secret_service_backend_mismatch")
        require(set(report.get("required_cases", [])) == REQUIRED,
            "secret_service_case_contract_mismatch")
        require(report.get("passed") is True and not report.get("missing_cases")
            and all(report.get("cases", {}).get(case, {}).get("passed") is True for case in REQUIRED),
            "secret_service_migration_incomplete")
        for field, remaining in (("cloud_cleanup", "remaining_users"), ("keyring_cleanup", "remaining_entries")):
            require(report.get(field, {}).get("passed") is True
                and not report.get(field, {}).get(remaining), "secret_service_" + field + "_failed")
        evidence = report["cases"]["secret_service_current_credentials_for_legacy_db"]
        require(evidence.get("backend") == "secret_service"
            and evidence.get("current_source_credentials_preserved") is True
            and set(evidence.get("database_origins", [])) == {"1memory", "memocap", "respire"},
            "secret_service_current_credential_evidence_missing")
        result.update(passed=True, required_observed=len(REQUIRED))
    except Exception as error:
        result["failure_code"] = str(error) if isinstance(error, RuntimeError) else type(error).__name__
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
