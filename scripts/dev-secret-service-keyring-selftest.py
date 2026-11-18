#!/usr/bin/env python3
"""Owned credential checks on a private bus or an explicitly verified hosted user bus."""
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
    except Exception as error:
        # Publish only fixed classifications and process state, never backend text.
        report["diagnostic_failed"] = True
        report["failure_code"] = "fixture_diagnostic_failed"
        if isinstance(error, RuntimeError) and str(error) in {
                "fixture_secret_service_daemon_exited",
                "fixture_secret_service_owner_mismatch", "credential_cases_incomplete"}:
            report["failure_code"] = str(error)
        elif isinstance(error, subprocess.TimeoutExpired):
            report["failure_code"] = "business_command_timeout"
        if manager.daemon is not None:
            daemon_exit = manager.daemon.poll()
            report["secret_service_daemon"] = {
                "state": "running" if daemon_exit is None else "exited",
                "exit_code": daemon_exit,
            }
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
    from unittest.mock import MagicMock, patch

    backend = load("pure_secret_service_environment", "dev-migration-secret-service.py")
    keys = object.__new__(backend.SecretServiceKeys)
    keys.bus = "unix:private-fixture"
    keys.bus_mode = "private"
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
    keys.bus_mode = "hosted-user"
    keys.bus = "unix:path=/run/user/123/bus"
    keys.private_env["XDG_RUNTIME_DIR"] = "/run/user/123"
    with patch.object(backend._base, "owned_path", lambda path: path):
        env = keys.configure_business_env({"HOME": "fixture-home", "USERPROFILE": "fixture-home"})
    assert env["RSRS_SS_FIXTURE_BUS"] == "hosted-user"
    assert env["DBUS_SESSION_BUS_ADDRESS"] == keys.bus and env["XDG_RUNTIME_DIR"] == "/run/user/123"
    assert env["HOME"] == env["USERPROFILE"] == "fixture-home"

    runtime, bus = MagicMock(), MagicMock()
    runtime.__str__.return_value = "/run/user/123"
    bus.__str__.return_value = "/run/user/123/bus"
    runtime.__truediv__.return_value = bus
    runtime.is_symlink.return_value = bus.is_symlink.return_value = False
    runtime.is_dir.return_value = bus.exists.return_value = True
    runtime.stat.return_value = SimpleNamespace(st_uid=123, st_mode=backend.stat.S_IFDIR | 0o700)
    bus.stat.return_value = SimpleNamespace(st_uid=123, st_mode=backend.stat.S_IFSOCK | 0o600)
    hosted = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}
    with patch.object(backend.sys, "platform", "linux"), \
            patch.object(backend.os, "getuid", return_value=123, create=True), \
            patch.object(backend, "Path", return_value=runtime), \
            patch.dict(os.environ, hosted, clear=True):
        session = backend.hosted_user_bus_environment()
        assert session == {"XDG_RUNTIME_DIR": "/run/user/123",
            "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/123/bus", "RSRS_SS_FIXTURE_BUS": "hosted-user"}
        for invalid in ({"RUNNER_ENVIRONMENT": "self-hosted"}, {"GITHUB_ACTIONS": "false"},
                        {"RSRS_SS_FIXTURE_BUS": "private"}):
            with patch.dict(os.environ, invalid):
                try:
                    backend.hosted_user_bus_environment()
                except RuntimeError as error:
                    assert str(error) == "hosted_user_bus_requires_dedicated_linux_runner"
                else:
                    raise AssertionError("unverified hosted session accepted")
        for owner, mode in ((999, backend.stat.S_IFSOCK), (123, backend.stat.S_IFREG)):
            bus.stat.return_value = SimpleNamespace(st_uid=owner, st_mode=mode)
            try:
                backend.hosted_user_bus_environment()
            except RuntimeError as error:
                assert str(error) == "hosted_user_bus_socket_invalid"
            else:
                raise AssertionError("unowned or nonsocket bus accepted")
    with patch.object(backend._base.TrackedKeys, "__init__", lambda *args: None), \
            patch.object(backend.sys, "platform", "linux"), patch.dict(os.environ, session, clear=True):
        try:
            backend.SecretServiceKeys(Path("unused"))
        except RuntimeError as error:
            assert str(error) == "private_fixture_session_bus_required"
        else:
            raise AssertionError("private mode accepted the hosted bus")

    items = []
    keys.verify_owner = lambda: None
    keys.collection = SimpleNamespace(get_all_items=lambda: list(items))
    for slot in ("super", "pass", "totp", "key-control", "login-control"):
        item = SimpleNamespace(get_attributes=lambda slot=slot: {
            "service": "rsrs", "target": "default", "application": "rust-keyring",
            "username": slot + ":login-" + "a" * 32})
        item.delete = lambda item=item: items.remove(item)
        items.append(item)
    keys.cleanup_business_entries()
    assert not items
    assert keys.business_cleanup == {"passed": True, "stage": "complete",
        "observed_entries": 5, "validated_entries": 5, "deleted_entries": 5, "remaining_entries": 0}
    assert keys.business_classification["known_prefix_counts"]["key-control:"] == 1
    assert keys.business_classification["known_prefix_counts"]["login-control:"] == 1
    assert keys.business_classification["owned_entries"] == 5
    assert keys.business_classification["unowned_entries"] == 0
    items.append(SimpleNamespace(get_attributes=lambda: {"service": "unknown"}))
    try:
        keys.cleanup_business_entries()
    except RuntimeError:
        assert len(items) == 1
        assert keys.business_cleanup == {"passed": False, "stage": "ownership_validation",
            "observed_entries": 1, "validated_entries": 0, "deleted_entries": 0, "remaining_entries": None}
        assert "unknown" not in json.dumps(keys.business_cleanup)
    else:
        raise AssertionError("unknown credential accepted")

    for username, service in (("login-control:legacy-" + "a" * 64, "rsrs"),
            ("login-control:login-" + "a" * 31, "rsrs"),
            ("login-control:login-" + "a" * 32 + ".backup", "rsrs"),
            ("login-control:login-" + "a" * 32, "foreign"),
            ("key-control:legacy-" + "a" * 64, "rsrs"),
            ("key-control:login-" + "a" * 31, "rsrs"),
            ("key-control:login-" + "a" * 32 + ".backup", "rsrs"),
            ("key-control:login-" + "a" * 32, "foreign")):
        items.clear()
        items.append(SimpleNamespace(get_attributes=lambda username=username, service=service: {
            "service": service, "target": "default", "application": "rust-keyring", "username": username}))
        try:
            keys.cleanup_business_entries()
        except RuntimeError:
            assert len(items) == 1 and keys.business_cleanup["deleted_entries"] == 0
            assert keys.business_cleanup["stage"] == "ownership_validation"
            assert username not in json.dumps(keys.business_cleanup)
        else:
            raise AssertionError("foreign or malformed key-control accepted")

    items.clear()
    for index in range(39):
        username = ("unknown:" if index in (27, 38) else "super:") + "login-" + f"{index:032x}"
        item = SimpleNamespace(get_attributes=lambda username=username: {
            "service": "rsrs", "target": "default", "application": "rust-keyring", "username": username})
        item.delete = lambda item=item: items.remove(item)
        items.append(item)
    try:
        keys.cleanup_business_entries()
    except RuntimeError as error:
        assert str(error) == "unexpected_private_credential"
        assert len(items) == 39 and keys.business_cleanup["deleted_entries"] == 0
        assert keys.business_cleanup["validated_entries"] == 27
        assert keys.business_classification["owned_entries"] == 37
        assert keys.business_classification["unowned_entries"] == 2
    else:
        raise AssertionError("mixed unknown collection was deleted")

    class FakeManager:
        def __init__(self, cleanup_ok=True):
            self.daemon = None
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
    parser.add_argument("--hosted-user-bus", action="store_true",
                        help="Use the verified dedicated Linux runner bus for real systemd registration")
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
        if args.hosted_user_bus:
            session = fixture.backend.hosted_user_bus_environment()
            os.environ.update(session)
            env.update(session)
        manager = fixture.backend.create(root / "keyring-home", hosted_user_bus=args.hosted_user_bus)
        code, report = business_check(manager, env, command, fixture.roundtrips, timeout=args.timeout)
    except Exception as error:
        report["diagnostic_failed"] = True
        if isinstance(error, RuntimeError) and str(error) in {
                "hosted_user_bus_requires_dedicated_linux_runner", "hosted_user_runtime_directory_invalid",
                "hosted_user_bus_socket_invalid", "hosted_user_bus_environment_mismatch",
                "hosted_user_systemd_owner_missing", "hosted_user_systemd_owner_mismatch",
                "fixture_bus_already_has_secret_service", "fixture_default_collection_not_empty",
                "fixture_secret_service_initialization_failed"}:
            report["failure_code"] = str(error)
    report["bus_mode"] = "hosted-user" if args.hosted_user_bus else "private"
    (root / "business-keyring-selftest.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"stage": report["stage"], "passed": report["passed"],
                      "business_passed": report.get("business_passed", False)}))
    return code


if __name__ == "__main__":
    sys.exit(main())
