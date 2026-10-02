#!/usr/bin/env python3
"""Fail closed unless all declared CLI supplements passed for one CI artifact."""
import argparse
import json
import os
from pathlib import Path
import re
import sys

SUPPLEMENTS = {"local_api", "ai_inject", "outbox", "legacy_vault"}
OUTBOX = {"foreground_save_during_network_wait", "independent_pull_decrypt",
          "scheduled_transport_retry", "finite_manual_boundary", "reset_old_response_rejection"}
AI = {"model_cpu_real", "inject_preview_install_remove", "inject_stale_revision_rejected",
      "inject_malformed_marker_rejected", "inject_legacy_marker_contract",
      "classify_save_provider_contract", "classify_tree_provider_contract",
      "classify_causal_plan", "classify_auto_applied", "tree_deepen_go_applied",
      "tree_deepen_auto_applied", "tree_cure_auto_applied"}
LEGACY = {"model_cpu_real", "local_v1_upgrade", "cloud_v2_recovery_upgrade",
          "cloud_v3_secret_key_recovery_upgrade"}


def require(value, code):
    if not value:
        raise RuntimeError(code)


def read(path):
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    require(isinstance(value, dict), "report_not_object")
    return value


def identity(report, args, source="source_sha", version="version"):
    require(report.get(source) == args.source_sha, "artifact_source_mismatch")
    require(report.get(version) == args.version, "artifact_version_mismatch")
    require(report.get("binary_sha256") == args.binary_sha256, "artifact_binary_mismatch")


def cases(report, required, code):
    observed = report.get("cases", {})
    require(all(observed.get(name, {}).get("passed") is True for name in required), code)


def verify(args, result):
    require(os.environ.get("GITHUB_ACTIONS") == "true", "github_actions_required")
    require(re.fullmatch("[0-9a-f]{40}", args.source_sha), "invalid_artifact_source")
    require(re.fullmatch("[0-9a-f]{64}", args.binary_sha256), "invalid_artifact_hash")
    base = read(args.cli_report)
    identity(base, args, version="observed_version")
    require(base.get("expected_version") == args.version, "base_expected_version_mismatch")
    require(base.get("server") == "https://dev.rsrs.rs", "base_server_mismatch")
    require(base.get("base_complete") is True and base.get("failed") == 0
            and not base.get("required_missing"), "cli_base_incomplete")
    catalog = base.get("catalog", {})
    require(not catalog.get("required_remaining"), "undelegated_requirement_remaining")
    require(set(base.get("supplemental_required", [])) == SUPPLEMENTS
            and set(catalog.get("supplemental_required", [])) == SUPPLEMENTS,
            "supplemental_contract_mismatch")
    required = catalog.get("required_assertions", [])
    require(required and len(required) == len(set(required)), "invalid_cli_case_catalog")
    observed = {row.get("case") for row in base.get("cases", [])
                if row.get("result") == "passed" and row.get("status") == "ok"}
    require(set(required).issubset(observed), "cli_required_observations_missing")
    result["components"]["cli"] = {"passed": True, "required_observed": len(required)}

    outbox = read(args.outbox)
    identity(outbox, args)
    require(outbox.get("passed") is True and not outbox.get("remaining"), "outbox_incomplete")
    cases(outbox, OUTBOX, "outbox_required_cases_missing")
    require(outbox.get("cleanup", {}).get("passed") is True, "outbox_cleanup_failed")
    result["components"]["outbox"] = {"passed": True, "required_observed": len(OUTBOX)}

    ai = read(args.ai_inject)
    identity(ai, args)
    require(ai.get("status") == "passed" and not ai.get("missing_cases"), "ai_inject_incomplete")
    cases(ai, AI, "ai_inject_required_cases_missing")
    require(ai.get("cloud_cleanup", {}).get("passed") is True, "ai_inject_cleanup_failed")
    result["components"]["ai_inject"] = {"passed": True, "required_observed": len(AI)}

    legacy = read(args.legacy_vault)
    identity(legacy, args)
    require(legacy.get("passed") is True and not legacy.get("missing_cases"), "legacy_vault_incomplete")
    cases(legacy, LEGACY, "legacy_vault_required_cases_missing")
    require(legacy.get("cloud_cleanup", {}).get("passed") is True, "legacy_vault_cleanup_failed")
    result["components"]["legacy_vault"] = {"passed": True, "required_observed": len(LEGACY)}

    local = read(args.local_api)
    identity(local, args, source="cli_source_sha")
    require(local.get("complete") is True and not local.get("uncovered")
            and not local.get("negative_uncovered") and not local.get("conditional"), "local_api_incomplete")
    actions = local.get("actions", [])
    expected_actions = json.loads(Path(__file__).with_name("dev-local-api-coverage.json").read_text(encoding="utf-8"))["actions"]
    require(len(actions) == 72 and {action.get("action") for action in actions}
            == {action["action"] for action in expected_actions} and all(action.get("passed") is True
            and action.get("observed_assertions", 0) >= 2 for action in actions), "local_api_observations_missing")
    require(local.get("cloud_cleanup") is True and not local.get("remaining_users"), "local_api_cleanup_failed")
    result["components"]["local_api"] = {"passed": True, "required_observed": len(actions)}
    result["complete"] = True
    result["conditional_unverified"] = catalog.get("conditional_unverified", [])
    result["excluded_not_implemented"] = catalog.get("excluded_not_implemented", [])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("cli-report", "outbox", "ai-inject", "local-api", "legacy-vault", "report"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("source-sha", "version", "binary-sha256"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    result = {"complete": False, "source_sha": args.source_sha, "version": args.version,
              "binary_sha256": args.binary_sha256, "components": {}}
    try:
        verify(args, result)
    except Exception as error:
        result["failure_code"] = str(error) if isinstance(error, RuntimeError) else type(error).__name__
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"complete": result["complete"], "components": result["components"],
                      "failure_code": result.get("failure_code")}))
    return 0 if result["complete"] else 1


if __name__ == "__main__":
    sys.exit(main())
