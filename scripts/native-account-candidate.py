#!/usr/bin/env python3
"""Run the unchanged Runtime account regression against two exact source commits.

The default retains the account case; --suite full runs every original business case.
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


def selected_cases(listing, suite):
    names = [line[:-6] for line in listing.splitlines() if line.endswith(": test")]
    require(names.count(CASE) == 1, "original_account_case_missing")
    if suite == "account":
        return [CASE]
    require(suite == "full", "unknown_business_suite")
    require(len(names) == len(set(names)) == sum(MODULE_COUNTS.values()),
            "business_case_inventory_mismatch")
    for module, count in MODULE_COUNTS.items():
        require(sum(name.startswith(module + "::") for name in names) == count,
                "business_module_inventory_mismatch")
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
    report = {"schema_version": 1, "kind": "unpublished-source-fixture",
              "case": CASE if args.suite == "account" else "full-business-suite", "suite": args.suite,
              "client2_host_prototype": args.compatibility_host,
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
        version = source_version(args.runtime_source, "runtime")
        cli_version = source_version(args.cli_source, "cli")
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
            cases = selected_cases(listing.decode(), args.suite)
            report["required_cases"] = cases
            test_args = [CASE, "--exact", "--test-threads=1"] if args.suite == "account" else ["--test-threads=1"]
            command = ["dbus-run-session", "--", "env", "RSRS_SS_FIXTURE_BUS=private",
                sys.executable, "-B", args.cli_source / "scripts/dev-secret-service-keyring-selftest.py",
                "--root", root / "keyring", "--", harness, *test_args]
            report["stage"] = "private_account_test"
            report["test_requested"] = True
            invoke(command, timeout=1000 if args.suite == "account" else 2700)
        report["stage"] = "result_verification"
        keyring = json.loads((root / "keyring/business-keyring-selftest.json").read_text())
        report["keyring"] = keyring
        require(keyring.get("passed") is True and keyring.get("business_passed") is True,
                "private_business_fixture_failed")
        require(digest(cli) == report["cli_binary_sha256"] and digest(runtime) == report["runtime_binary_sha256"]
                and digest(harness) == report["harness_sha256"], "executed_binaries_changed")
        captured = log.read_bytes()
        require(f"test result: ok. {len(cases)} passed; 0 failed;".encode() in captured,
                "required_business_cases_did_not_pass")
        require(all(f"test {case} ... ok".encode() in captured.splitlines() for case in cases),
                "required_business_case_result_missing")
        if args.compatibility_host:
            checks = compatibility_host_checks(captured)
            expected = {"import-target", "restart-target"}
            if args.suite == "full":
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
    parser.add_argument("--suite", choices=("account", "full"), default="account")
    parser.add_argument("--compatibility-host", action="store_true")
    def interrupted(_number, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    return run(parser.parse_args())


if __name__ == "__main__":
    sys.exit(main())
