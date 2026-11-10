#!/usr/bin/env python3
"""Preservation smoke using official CLI 1.0.20 and a locally built candidate.

This checks lifecycle deferral, not new Runtime wire compatibility or inference.
All processes and files are isolated; no fixture is downloaded by this script.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request

LEGACY_SHA256 = "c03c131c61819a5f4d132cfe328f7c1da82c2f0b21a9c87d2b8870d1541a4c3e"


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--legacy-binary", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    legacy = args.legacy_binary.resolve(strict=True)
    candidate = args.candidate.resolve(strict=True)
    if digest(legacy) != LEGACY_SHA256:
        raise ValueError("expected the official GNU CLI v1.0.20 binary")
    if os.uname().sysname != "Linux" or os.uname().machine != "x86_64":
        raise ValueError("this fixture requires native Linux x86_64")
    report = {"legacy_version": "1.0.20", "legacy_sha256": LEGACY_SHA256,
              "candidate_sha256": digest(candidate), "checks": [], "static_rejections": [],
              "scope": "native legacy service preservation; no inference or new wire acceptance"}
    with tempfile.TemporaryDirectory(prefix="rsrs-legacy-preservation-") as temporary:
        root = Path(temporary)
        installation = root / "installation"
        binary = installation / "bin" / "rsrs"
        binary.parent.mkdir(parents=True)
        shutil.copyfile(legacy, binary)
        binary.chmod(0o700)
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith(("RSRS_", "ONEMEMORY_", "RESPIRE_", "XDG_"))}
        environment.update({"HOME": str(root / "home"), "RSRS_DATA_DIR": str(installation),
                            "RSRS_BIN_DIR": str(binary.parent), "RSRS_RPC_PORT": str(port),
                            "RSRS_CORE_TEST_MODE": "1",
                            "XDG_CONFIG_HOME": str(root / "config"),
                            "XDG_DATA_HOME": str(root / "share"),
                            "XDG_CACHE_HOME": str(root / "cache")})
        for directory in (root / "home", root / "config", root / "share", root / "cache"):
            directory.mkdir()
        version = subprocess.run([str(binary), "--version"], env=environment,
                                 capture_output=True, text=True, timeout=10, check=True)
        if version.stdout.strip() != "rsrs 1.0.20":
            raise AssertionError("legacy executable version differs")
        log = (root / "legacy.log").open("wb")
        child = subprocess.Popen([str(binary), "--runtime-internal", "--no-open"],
                                 env=environment, stdout=log, stderr=log)
        try:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            def health():
                with opener.open(f"http://127.0.0.1:{port}/api/health", timeout=2) as response:
                    return json.load(response)
            deadline = time.monotonic() + 20
            while True:
                if child.poll() is not None:
                    raise RuntimeError("isolated legacy service exited before readiness: " + (root / "legacy.log").read_text(errors="replace"))
                try:
                    initial = health()
                    break
                except (OSError, ValueError):
                    if time.monotonic() >= deadline:
                        raise TimeoutError("isolated legacy service did not become healthy")
                    time.sleep(0.1)
            if initial.get("pid") != child.pid or initial.get("bin") != "1.0.20":
                raise AssertionError("legacy health identity differs")
            endpoint = installation / "runtime" / "endpoint.json"
            endpoint_before = endpoint.read_bytes()
            takeover = installation / "runtime" / "takeover"
            if takeover.exists():
                raise AssertionError("legacy fixture unexpectedly contains takeover state")
            for command in (("runtime", "install"), ("runtime", "update"),
                            ("runtime", "start"), ("runtime", "restart"),
                            ("runtime", "autostart", "enable", "--now")):
                result = subprocess.run([str(candidate), "--json", *command], env=environment,
                                        capture_output=True, text=True, timeout=20)
                output = result.stdout + result.stderr
                if result.returncode == 0 or "legacy_runtime_migration_required" not in output:
                    raise AssertionError(f"{command}: expected explicit migration deferral: {output}")
                current = health()
                if child.poll() is not None or current.get("pid") != child.pid:
                    raise AssertionError(f"{command}: old service was stopped/replaced")
                if digest(binary) != LEGACY_SHA256 or endpoint.read_bytes() != endpoint_before:
                    raise AssertionError(f"{command}: old image or endpoint changed")
                if takeover.exists():
                    raise AssertionError(f"{command}: rejected operation created takeover state")
                if (installation / "runtime.json").exists():
                    raise AssertionError(f"{command}: new Runtime selection was published")
                for name in ("registration.json", "maintenance.json"):
                    if (installation / "runtime" / "autostart" / name).exists():
                        raise AssertionError(f"{command}: lifecycle state {name} was created")
                status = subprocess.run([str(binary), "--json", "--runtime-internal", "--status"],
                                        env=environment, capture_output=True, text=True, timeout=10)
                if status.returncode or json.loads(status.stdout).get("summary", {}).get("state") != "up":
                    raise AssertionError(f"{command}: original CLI status failed: {status.stdout}")
                report["checks"].append({"command": list(command), "deferred": True,
                                         "original_service_and_cli_available": True,
                                         "original_image_endpoint_and_selection_preserved": True,
                                         "takeover_directory_not_created": True})
        finally:
            if child.poll() is None:
                child.terminate()
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=10)
            log.close()
        for command in (("runtime", "start"), ("runtime", "restart")):
            stopped = root / ("stopped-" + command[1])
            stopped.mkdir()
            session = stopped / "session.json"
            session.write_bytes(b"legacy session fixture")
            stopped_environment = dict(environment, RSRS_DATA_DIR=str(stopped),
                                       RSRS_BIN_DIR=str(stopped / "bin"))
            result = subprocess.run([str(candidate), "--json", *command], env=stopped_environment,
                                    capture_output=True, text=True, timeout=20)
            if result.returncode == 0 or "legacy_runtime_migration_required" not in result.stdout + result.stderr:
                raise AssertionError(f"{command}: stopped legacy installation did not defer")
            if session.read_bytes() != b"legacy session fixture" or list(stopped.iterdir()) != [session]:
                raise AssertionError(f"{command}: stopped legacy rejection wrote installation state")
            report["static_rejections"].append({"command": list(command),
                                                "session_preserved": True,
                                                "installation_tree_unchanged": True})
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Passed {len(report['checks'])} native legacy preservation checks and "
          f"{len(report['static_rejections'])} stopped-installation no-write checks")


if __name__ == "__main__":
    main()
