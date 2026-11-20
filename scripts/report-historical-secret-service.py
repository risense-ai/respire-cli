"""Publish only the fixed diagnostic fields from a historical Secret Service run."""
import json
import os
from pathlib import Path
import sys


def diagnostic(root, source, status):
    public = {"source": source, "exit_code": status, "fixture_report_present": False}
    path = root / source / "results" / "real-account-return-verification.json"
    if not path.is_file():
        return public
    report, = json.loads(path.read_text(encoding="utf-8"))
    public.update(fixture_report_present=True, passed=report["passed"] is True,
                  historical_sync_verified=report.get("post_upgrade_sync_checked") is True)
    sync = report.get("post_upgrade_sync_diagnostic", {})
    cleanup = report.get("native_credential_cleanup", {})
    provider = cleanup.get("provider_daemon", {})
    # These structures are constructed by the fixture from fixed classes and process state.
    for key in ("provider_observation", "cli_failure"):
        if key in sync:
            public[key] = sync[key]
    if provider:
        public["provider_daemon"] = provider
    public["native_cleanup_passed"] = cleanup.get("passed") is True
    public["cloud_cleanup_passed"] = report.get("cloud_cleanup", {}).get("passed") is True
    return public


if __name__ == "__main__":
    root, output, status = sys.argv[1:]
    source = os.environ["HISTORICAL_SOURCE"]
    assert source in ("v1.0.7", "v1.0.20")
    receipt = json.dumps(diagnostic(Path(root), source, int(status)), indent=2)
    Path(output).write_text(receipt + "\n", encoding="utf-8")
    print(receipt)
