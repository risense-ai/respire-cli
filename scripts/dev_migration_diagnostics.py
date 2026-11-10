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
