"""Publish only the fixed diagnostic fields from a historical Secret Service run."""
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
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



CRITICAL = re.compile(
    rb"(?m)^(?:\*\* )?(?:\(gnome-keyring-daemon:[0-9]+\): )?"
    rb"(?:(?:GLib(?:-GIO|-GObject)?|Gkm|Gkd|Egg|gnome-keyring-daemon)-)?"
    rb"CRITICAL \*\*: (?P<message>[^\r\n]+)")
ASSERTION = re.compile(
    rb"(?:[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3,6}: )?"
    rb"(?P<function>[A-Za-z_][A-Za-z0-9_]{0,79}): assertion '[^\r\n]+' failed")


def critical_symbol(stderr, exported):
    messages = list(CRITICAL.finditer(stderr))
    if messages:
        assertion = ASSERTION.fullmatch(messages[-1]["message"])
        if assertion and assertion["function"] in exported:
            return assertion["function"].decode("ascii")
    return "unknown"


def exported_functions():
    system = Path("/usr/lib/aarch64-linux-gnu")
    libraries = [system / name for name in (
        "libglib-2.0.so.0", "libgobject-2.0.so.0", "libgio-2.0.so.0",
        "libgcr-base-3.so.1", "libgck-1.so.0", "libsecret-1.so.0")]
    daemon = shutil.which("gnome-keyring-daemon")
    if daemon:
        libraries.append(Path(daemon))
    functions = set()
    for path in libraries:
        if not path.is_file():
            continue
        result = subprocess.run(["nm", "-D", "--defined-only", str(path)],
                                check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        for line in result.stdout.splitlines():
            fields = line.split()
            if len(fields) == 3 and fields[1] in (b"T", b"W", b"i"):
                functions.add(fields[2].split(b"@", 1)[0])
    return functions


def daemon_stderr(runner_temp):
    paths = list(runner_temp.glob("rsrs-up-*/keyring-home/provider.stderr"))
    if len(paths) != 1:
        return b""
    path, = paths
    for directory in (path.parent.parent, path.parent):
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.getuid():
            return b""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.getuid():
            return b""
        # Only inspect the trailing log window locally. No log bytes enter the receipt.
        stream.seek(max(0, info.st_size - 65536))
        return stream.read(65536)


if __name__ == "__main__":
    root, output, status = sys.argv[1:]
    data = diagnostic(Path(root), "v1.0.7", int(status))
    provider = data.get("provider_daemon", {})
    if provider.get("exit_code_at_cleanup_start") == -5 and provider.get("abort_type") == "glib_fatal_critical":
        data["glib_critical_function"] = critical_symbol(
            daemon_stderr(Path(os.environ["RUNNER_TEMP"])), exported_functions())
    receipt = json.dumps(data, indent=2)
    Path(output).write_text(receipt + "\n", encoding="utf-8")
    print(receipt)
