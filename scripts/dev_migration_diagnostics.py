"""Bounded migration diagnostics: no identities, paths, receipts or raw errors."""


def migration_failure_diagnostics(envelope):
    result = {"migration_outcome": None, "migration_request_phase": None}
    if not isinstance(envelope, dict) or envelope.get("command") != "migrate":
        return result
    summary = envelope.get("summary")
    if not isinstance(summary, dict):
        return result
    for source, target, allowed in (
        ("outcome", "migration_outcome", ("unknown", "completed", "already_migrated")),
        ("request_phase", "migration_request_phase", ("initial_request", "result_query")),
    ):
        value = summary.get(source)
        if type(value) is str and value in allowed:
            result[target] = value
    return result


def migration_execution_state(fixture_root, env, arguments, envelope):
    """Inspect only owned migration metadata and SQLite health after a failed call."""
    from contextlib import closing
    import hashlib
    import json
    import os
    from pathlib import Path
    import re
    import sqlite3
    from native_fixture_process import canonical_scope_path

    result = {"status": "unavailable"}
    try:
        def scope_path(path):
            raw = str(path)
            if os.name == "nt" and raw.startswith("\\\\?\\UNC\\"):
                raw = "\\\\" + raw[8:]
            elif os.name == "nt" and raw.startswith("\\\\?\\"):
                raw = raw[4:]
            return Path(raw).resolve()

        base = scope_path(fixture_root)
        if not base.is_dir():
            raise ValueError("diagnostic fixture root missing")

        def owned(path):
            path = Path(path)
            for parent in (path, *path.parents):
                if parent.is_symlink() or parent.is_junction():
                    raise ValueError("diagnostic link rejected")
            resolved = scope_path(path)
            if resolved == base or not resolved.is_relative_to(base):
                raise ValueError("diagnostic path outside fixture")
            return resolved

        home = owned(env["HOME"])
        root = owned(env.get("RSRS_DATA_DIR") or home / ".rsrs")
        source = arguments[arguments.index("--source") + 1]
        account = arguments[arguments.index("--account") + 1]
        if not re.fullmatch(r"[0-9a-f]{64}", source) or not re.fullmatch(r"[A-Za-z0-9_-]+", account):
            raise ValueError("invalid diagnostic selection")
        errors = envelope.get("errors", []) if isinstance(envelope, dict) else []
        matches = [match[1] for error in errors if isinstance(error, str)
            for match in re.finditer(r"\bmigration_outcome_unknown operation_id=([0-9a-f-]{36})(?=[;\s]|$)", error)]
        if len(matches) != 1:
            return {"status": "operation_binding_missing"}
        operation = matches[0]
        if not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", operation):
            raise ValueError("invalid diagnostic operation")

        def bound(original):
            return isinstance(original, dict) and original.get("operation_id") == operation \
                and original.get("source_id") == source and original.get("account") == account

        def database_state(path, lock=False):
            path = owned(path)
            if not path.exists():
                return {"state": "absent"}
            if not path.is_file():
                return {"state": "invalid_type"}
            try:
                with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=0.1)) as connection:
                    connection.execute("PRAGMA query_only=ON")
                    if lock:
                        connection.execute("PRAGMA schema_version").fetchone()
                        return {"state": "readable"}
                    valid = all(row[0] == "ok" for row in connection.execute("PRAGMA integrity_check"))
                    return {"state": "ok" if valid else "not_ok"}
            except sqlite3.Error as error:
                code = getattr(error, "sqlite_errorcode", None)
                return {"state": "busy" if type(code) is int and code & 255 in (5, 6) else "sqlite_error",
                        "sqlite_code": code if type(code) is int else None}

        def staged_conversion(stage):
            path = owned(stage / 'onememory.db')
            if not path.is_file():
                return {'status': 'legacy_database_absent'}
            try:
                with closing(sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=0.1)) as connection:
                    connection.execute('PRAGMA query_only=ON')
                    journal = connection.execute('PRAGMA journal_mode').fetchone()[0]
                    total, converted = connection.execute('''SELECT COUNT(*),
                        COUNT(CASE WHEN substr(ciphertext, 1, 8) = 'rsrs:v1:' THEN 1 END)
                        FROM memories''').fetchone()
                    triggers = connection.execute('''SELECT COUNT(*) FROM sqlite_master
                        WHERE type = 'trigger' AND name IN ('sync_capture_insert', 'sync_capture_update')''').fetchone()[0]
            except sqlite3.Error as error:
                return {'status': 'sqlite_error', 'sqlite_code': getattr(error, 'sqlite_errorcode', None)}
            result = {'status': 'collected', 'memory_rows': total, 'converted_rows': converted,
                      'sync_capture_triggers': triggers,
                      'journal_mode': journal if journal in ('delete', 'wal', 'truncate', 'persist', 'memory', 'off') else 'other'}
            path = owned(stage / 'session.json')
            if path.is_file():
                session = json.loads(path.read_text(encoding='utf-8'))
                result['session_rewritten'] = session.get('crypto_namespace') == 'rsrs:v1:' and session.get('keyring_account') == 'legacy-' + source[:16]
            return result

        host_records = []
        directory = owned(root / "runtime/autostart/migrations")
        if directory.exists():
            for path in directory.glob("*.json"):
                record = json.loads(owned(path).read_text(encoding="utf-8"))
                if bound(record.get("operation")):
                    host_records.append(record)
        result = {"status": "collected", "host_record": "absent"}
        if len(host_records) > 1:
            return {"status": "host_record_ambiguous"}
        if host_records:
            record = host_records[0]
            result["host_record"] = "matched"
            for field in ("sent", "finished", "was_serving", "store_ready"):
                result[field] = record.get(field) if type(record.get(field)) is bool else None
            result["terminal_receipt_present"] = record.get("terminal_receipt") is not None
            result["schema_rejection_present"] = record.get("schema_rejection") is not None
        marker = owned(root / "runtime/autostart/maintenance.json")
        result["maintenance"] = "absent"
        if marker.exists():
            phase = json.loads(marker.read_text(encoding="utf-8")).get("phase")
            result["maintenance"] = {"Paused": "paused", "Starting": "starting", "Verified": "verified"}.get(phase, "unrecognized") if type(phase) is str else "unrecognized"
        result["installation_lock"] = database_state(root / "lock.db", lock=True)
        destination = owned(root / "accounts" / account)
        result["destination_exists"] = destination.is_dir()
        result["destination_receipt_exists"] = owned(destination / ".rsrs-migration.json").is_file()
        intent_path = owned(home / ".rsrs-migration-intents" / (operation + ".json"))
        result["intent"] = "absent"
        if intent_path.exists():
            data = intent_path.read_bytes()
            if not data.endswith(b"\n"):
                raise ValueError("diagnostic intent is truncated")
            frames = [json.loads(frame) for frame in data.splitlines()]
            phases = ("copying", "awaiting_credentials", "transforming", "ready", "rejected_schema")
            if not frames or any(not bound(frame.get("original")) or frame.get("phase") not in phases for frame in frames):
                raise ValueError("invalid diagnostic intent")
            intent = frames[-1]
            result.update(intent="matched", intent_phase=intent["phase"], intent_frames=len(frames))
            stage = owned(intent["stage"])
            if stage.parent != owned(home / ".rsrs-migration-staging"):
                raise ValueError("diagnostic stage root mismatch")
            result["staging_exists"] = stage.is_dir()
            result["staging_receipt_exists"] = owned(stage / ".rsrs-migration.json").is_file()
            result["staging_databases"] = {name: database_state(stage / name) for name in ("onememory.db", "rsrs.db")}
            if intent['phase'] == 'transforming':
                result['staging_conversion'] = staged_conversion(stage)
        result["destination_databases"] = {name: database_state(destination / name) for name in ("onememory.db", "rsrs.db")}
        if os.name == "nt":
            import winreg
            namespace = "Software\\Risense\\Respire\\MigrationIntentsV1\\"
            key = namespace + hashlib.sha256(canonical_scope_path(home).lower().encode()).hexdigest()
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key, 0,
                        winreg.KEY_QUERY_VALUE | winreg.KEY_WOW64_64KEY) as handle:
                    raw, kind = winreg.QueryValueEx(handle, operation)
                fence = json.loads(raw) if kind == winreg.REG_BINARY else None
                result["registry_fence"] = "matched" if isinstance(fence, dict) and fence.get("operation") == operation \
                    and fence.get("source") == source and fence.get("account") == account.lower() else "invalid"
            except (ValueError, TypeError):
                result["registry_fence"] = "invalid"
            except FileNotFoundError:
                result["registry_fence"] = "absent"
            except OSError as error:
                code = getattr(error, "winerror", None)
                result["registry_fence"] = "unavailable"
                result["registry_winerror"] = code if type(code) is int else None
        return result
    except (OSError, ValueError, TypeError, KeyError, IndexError, AttributeError):
        # Diagnostics are explicit and never change or hide the original failed migration.
        return {"status": "invalid_or_unavailable"}


def script_failure_location(error, script):
    """Report source coordinates only, never exception arguments or frame locals."""
    location = {}
    trace = error.__traceback__
    while trace is not None:
        if trace.tb_frame.f_code.co_filename == script:
            location = {"line": trace.tb_lineno, "function": trace.tb_frame.f_code.co_name}
        trace = trace.tb_next
    return location
