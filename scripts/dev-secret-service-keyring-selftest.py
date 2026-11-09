#!/usr/bin/env python3
"""Hosted private D-Bus credential checks, optionally around existing business tests."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_command(command, *, env, check, timeout):
    with subprocess.Popen(command, env=env, start_new_session=True) as child:
        try:
            return subprocess.CompletedProcess(command, child.wait(timeout=timeout))
        except BaseException:
            # Stop the business process group before removing its private credentials.
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait()
            raise


def business_check(manager, env, command, roundtrips, run=run_command, *, timeout=900):
    report = {"passed": False, "stage": "private_environment", "cases": {},
              "business_passed": False, "keyring_cleanup": {"passed": False}}
    business_exit = None
    try:
        env = manager.configure_business_env(env)
        manager.verify_owner()
        report["stage"] = "credential_before"
        roundtrips(manager, report["cases"])
        report["credential_before_passed"] = len(report["cases"]) == 8
        if not report["credential_before_passed"]:
            raise RuntimeError("credential_cases_incomplete")
        report["stage"] = "business"
        result = run(command, env=env, check=False, timeout=timeout)
        business_exit = result.returncode
        report["business_passed"] = business_exit == 0
        report["stage"] = "credential_after"
        manager.verify_owner()
        after = {}
        roundtrips(manager, after)
        report["credential_after_passed"] = len(after) == 8
        if not report["credential_after_passed"]:
            raise RuntimeError("credential_cases_incomplete")
        report["stage"] = "complete"
    except Exception:
        # Do not publish backend exceptions, command arguments, paths or bus addresses.
        report["diagnostic_failed"] = True
    finally:
        try:
            manager.cleanup_business_entries()
            report["business_credential_cleanup_passed"] = True
        except Exception:
            report["business_credential_cleanup_passed"] = False
        try:
            report["keyring_cleanup"] = manager.cleanup()
        except Exception:
            report["keyring_cleanup"] = {"passed": False}
    report["passed"] = (report["stage"] == "complete" and report["business_passed"]
                        and report["business_credential_cleanup_passed"]
                        and report["keyring_cleanup"].get("passed") is True)
    # Keep a real business failure even if a later probe or cleanup also fails.
    return (business_exit if business_exit is not None and business_exit > 0
            else 0 if report["passed"] else 1), report


def self_test():
    from types import SimpleNamespace
    from unittest.mock import patch

    backend = load("pure_secret_service_environment", "dev-migration-secret-service.py")
    keys = object.__new__(backend.SecretServiceKeys)
    keys.bus = "unix:private-fixture"
    keys.private_env = {key: "private-fixture" for key in (
        "XDG_DATA_HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_RUNTIME_DIR")}
    with patch.object(backend._base, "owned_path", lambda path: path):
        env = keys.configure_business_env({"HOME": "fixture-home", "USERPROFILE": "fixture-home",
            "DBUS_SESSION_BUS_ADDRESS": "runner-bus", "DBUS_STARTER_ADDRESS": "runner-bus",
            "GNOME_KEYRING_CONTROL": "runner-keyring", "XDG_DATA_HOME": "runner-data",
            "GH_TOKEN": "not-for-product"})
    assert env["DBUS_SESSION_BUS_ADDRESS"] == keys.bus
    assert all(env[key] == value for key, value in keys.private_env.items())
    assert not any(key in env for key in ("DBUS_STARTER_ADDRESS", "GNOME_KEYRING_CONTROL", "GH_TOKEN"))
    assert env["HOME"] == env["USERPROFILE"] == "fixture-home"

    items = []
    keys.verify_owner = lambda: None
    keys.collection = SimpleNamespace(get_all_items=lambda: list(items))
    for slot in ("super", "pass", "totp"):
        item = SimpleNamespace(get_attributes=lambda slot=slot: {
            "service": "rsrs", "target": "default", "application": "rust-keyring",
            "username": slot + ":login-" + "a" * 32})
        item.delete = lambda item=item: items.remove(item)
        items.append(item)
    keys.cleanup_business_entries()
    assert not items
    items.append(SimpleNamespace(get_attributes=lambda: {"service": "unknown"}))
    try:
        keys.cleanup_business_entries()
    except RuntimeError:
        assert len(items) == 1
    else:
        raise AssertionError("unknown credential accepted")

    class FakeManager:
        def __init__(self, cleanup_ok=True):
            self.cleaned = False
            self.cleanup_ok = cleanup_ok
            self.owners = 0

        def configure_business_env(self, env):
            return dict(env, fixture_private=True)

        def verify_owner(self):
            assert not self.cleaned
            self.owners += 1

        def cleanup_business_entries(self):
            assert not self.cleaned

        def cleanup(self):
            self.cleaned = True
            return {"passed": self.cleanup_ok}

    def roundtrips(manager, cases):
        assert not manager.cleaned
        cases.update({str(index): {"passed": True} for index in range(8)})

    for business_exit, cleanup_ok in ((0, True), (17, True), (0, False), (17, False)):
        manager = FakeManager(cleanup_ok)

        def run(command, **kwargs):
            assert command == ["fake-business"] and kwargs["env"]["fixture_private"]
            assert kwargs["check"] is False and kwargs["timeout"] == 900
            assert not manager.cleaned
            return SimpleNamespace(returncode=business_exit)

        code, report = business_check(manager, {}, ["fake-business"], roundtrips, run)
        assert code == (business_exit or (0 if cleanup_ok else 1))
        assert manager.cleaned and manager.owners == 2
        assert report["passed"] == (business_exit == 0 and cleanup_ok)
        assert report["credential_before_passed"] and report["credential_after_passed"]

    manager = FakeManager()
    def full_run(command, **kwargs):
        assert command == ["fake-business"] and kwargs["timeout"] == 6600
        return SimpleNamespace(returncode=0)
    code, report = business_check(manager, {}, ["fake-business"], roundtrips, full_run, timeout=6600)
    assert code == 0 and report["passed"] and manager.cleaned

    def failed_run(*args, **kwargs):
        raise RuntimeError("sensitive-data-must-not-be-published")

    manager = FakeManager()
    code, report = business_check(manager, {}, ["fake-business"], roundtrips, failed_run)
    assert code == 1 and manager.cleaned and report["stage"] == "business"
    assert "sensitive-data" not in json.dumps(report)

    def failed_after(manager, cases):
        if manager.owners == 2:
            raise RuntimeError("sensitive-after-check")
        roundtrips(manager, cases)

    manager = FakeManager()
    code, report = business_check(manager, {}, ["fake-business"], failed_after,
        lambda *args, **kwargs: SimpleNamespace(returncode=17))
    assert code == 17 and manager.cleaned and report["stage"] == "credential_after"
    assert report["business_credential_cleanup_passed"] and not report["passed"]
    assert "sensitive-after" not in json.dumps(report)
    print(json.dumps({"stage": "pure_selftest", "passed": True}))
    return 0


def main():
    if sys.argv[1:] == ["--self-test"]:
        return self_test()
    fixture = load("secret_service_credential_check", "dev-migration-keyring-selftest.py")
    fixture.backend = load("secret_service_owned_credentials", "dev-migration-secret-service.py")
    fixture.backend.require(sys.platform == "linux", "linux_secret_service_fixture_required")
    if "--" not in sys.argv[1:]:
        return fixture.main()
    separator = sys.argv.index("--")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=900)
    args = parser.parse_args(sys.argv[1:separator])
    fixture.backend.require(1 <= args.timeout <= 6600, "business_timeout_out_of_bounds")
    command = sys.argv[separator + 1:]
    fixture.backend.require(bool(command), "business_command_required")
    root = fixture.backend.owned_path(args.root)
    fixture.backend.require(args.root.is_absolute() and not root.exists(), "fixture_root_not_fresh")
    root.mkdir(mode=0o700)
    report = {"passed": False, "stage": "daemon_start"}
    code = 1
    try:
        home = root / "business-home"
        home.mkdir(mode=0o700)
        env = dict(os.environ, HOME=str(home), USERPROFILE=str(home))
        manager = fixture.backend.create(root / "keyring-home")
        code, report = business_check(manager, env, command, fixture.roundtrips, timeout=args.timeout)
    except Exception:
        report["diagnostic_failed"] = True
    (root / "business-keyring-selftest.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"stage": report["stage"], "passed": report["passed"],
                      "business_passed": report.get("business_passed", False)}))
    return code


if __name__ == "__main__":
    sys.exit(main())
