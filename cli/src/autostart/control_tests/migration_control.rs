//! Synthetic migration receipts and bounded recovery files, with no Runtime launch.
use super::*;
use serde_json::{json, Value};

fn operation(root: &Path) -> Result<HostMigrationOperation> {
    let mut operation = HostMigrationOperation {
        schema_version: HOST_MIGRATION_SCHEMA_V,
        operation_id: "0cef37f5-a863-4d25-b38a-c3988f94b069".into(),
        key: "0cef37f5-a863-4d25-b38a-c3988f94b069".into(),
        installation_root: root.to_path_buf(),
        profile: root.to_path_buf(),
        identity: HostAuthIdentity::Absent,
        source_id: "a".repeat(64),
        account: "synthetic-account".into(),
        fingerprint: String::new(),
    };
    operation.fingerprint = super::super::hash(&operation.fingerprint_bytes()?);
    Ok(operation)
}

fn receipt(
    original: &HostMigrationOperation,
    outcome: HostMigrationOutcome,
) -> HostMigrationResult {
    let details = match outcome {
        HostMigrationOutcome::Completed => json!({"state":"migrated","account":original.account,
            "dir":original.installation_root.join("accounts").join(&original.account),"original_preserved":true}),
        HostMigrationOutcome::AlreadyMigrated => json!({"state":"already_migrated"}),
        HostMigrationOutcome::Unknown => Value::Null,
    };
    HostMigrationResult {
        operation_id: original.operation_id.clone(),
        fingerprint: original.fingerprint.clone(),
        identity: original.identity.clone(),
        outcome,
        details,
    }
}

fn response(original: &HostMigrationOperation, outcome: HostMigrationOutcome) -> Value {
    let unknown = outcome == HostMigrationOutcome::Unknown;
    json!({"v":1,"id":"migration-request","pid":42,"bin":"rsrs-runtime",
        "operation_id":original.operation_id,"idempotency_key":original.key,"data_dir":original.profile,
        "ok":!unknown,"exit":if unknown {2} else {0},
        "code":if unknown {Some("migration_outcome_unknown")} else {None},
        "envelope":{"command":"migration-control","status":if unknown {"fail"} else {"ok"},
            "summary":receipt(original,outcome),"details":null,"actions":[],"errors":[],"related":[],
            "items":[{"name":"control_ready","status":"ok","value":"true"},
                     {"name":"store_ready","status":"skip","value":"false"}]}})
}

fn request(original: &HostMigrationOperation, method: &str) -> Result<RpcRequest> {
    Ok(serde_json::from_value(
        json!({"v":1,"id":"migration-request","method":method,"args":[],
        "operation_id":original.operation_id,"idempotency_key":original.key}),
    )?)
}

#[test]
fn migration_recovery_files_preserve_terminal_details_and_do_not_rewrite_input() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path().canonicalize()?;
    let path = root.join("migration.json");
    assert!(read_original(&path)?.is_none());
    let original = operation(&root)?;
    let context = Original {
        schema_rejection: None,
        terminal_receipt: Some(receipt(&original, HostMigrationOutcome::AlreadyMigrated)),
        operation: original,
        token: "synthetic-token".into(),
        coordinator: "synthetic-coordinator".into(),
        was_serving: false,
        store_ready: false,
        sent: true,
        finished: true,
    };
    let bytes = serde_json::to_vec(&context)?;
    std::fs::write(&path, &bytes)?;
    let (loaded, digest) = read_original(&path)?.context("saved migration recovery")?;
    assert!(loaded.finished && loaded.sent);
    assert_eq!(
        loaded.operation.operation_id,
        context.operation.operation_id
    );
    assert_eq!(
        loaded.terminal_receipt.context("terminal receipt")?.details["state"],
        "already_migrated"
    );
    assert_eq!(digest, super::super::hash(&bytes));
    assert_eq!(std::fs::read(&path)?, bytes);
    let mut legacy = serde_json::to_value(&context)?;
    legacy
        .as_object_mut()
        .context("recovery object")?
        .remove("terminal_receipt");
    std::fs::write(&path, serde_json::to_vec(&legacy)?)?;
    assert!(read_original(&path)?
        .context("legacy context")?
        .0
        .terminal_receipt
        .is_none());
    legacy["unexpected"] = json!(true);
    std::fs::write(&path, serde_json::to_vec(&legacy)?)?;
    assert!(read_original(&path).is_err());
    std::fs::write(&path, b"invalid JSON")?;
    assert!(read_original(&path).is_err());
    assert_eq!(std::fs::read(&path)?, b"invalid JSON");

    // Keep the schema valid so only the file-size boundary can reject this record.
    let bound = 16 * 1024;
    let mut bounded = serde_json::to_value(&context)?;
    bounded["token"] = json!("");
    let overhead = serde_json::to_vec(&bounded)?.len();
    assert!(overhead < bound);
    bounded["token"] = json!("x".repeat(bound - overhead));
    let at_limit = serde_json::to_vec(&bounded)?;
    assert_eq!(at_limit.len(), bound);
    let _: Original = serde_json::from_slice(&at_limit)?;
    std::fs::write(&path, &at_limit)?;
    assert!(read_original(&path)?.is_some());
    assert_eq!(std::fs::read(&path)?, at_limit);
    bounded["token"] = json!("x".repeat(bound - overhead + 1));
    let oversized = serde_json::to_vec(&bounded)?;
    assert_eq!(oversized.len(), bound + 1);
    let _: Original = serde_json::from_slice(&oversized)?;
    std::fs::write(&path, &oversized)?;
    let error = read_original(&path)
        .err()
        .context("oversized valid recovery record must be rejected")?;
    assert_eq!(error.to_string(), "invalid migration recovery metadata");
    assert_eq!(std::fs::read(&path)?, oversized);
    assert!(read_original(&root).is_err());
    #[cfg(unix)]
    {
        let linked = root.join("linked.json");
        // A valid direct target isolates link rejection from JSON/size rejection.
        std::fs::write(&path, &bytes)?;
        assert!(read_original(&path)?.is_some());
        std::os::unix::fs::symlink(&path, &linked)?;
        let error = read_original(&linked)
            .err()
            .context("symlink to valid recovery record must be rejected")?;
        assert_eq!(error.to_string(), "migration recovery path is a symlink");
        assert_eq!(std::fs::read(&path)?, bytes);
    }
    assert!(canonical_id(&context.operation.operation_id));
    for id in [
        "",
        "not-a-uuid",
        "0CEF37F5-A863-4D25-B38A-C3988F94B069",
        "0cef37f5-a863-5d25-b38a-c3988f94b069",
    ] {
        assert!(!canonical_id(id));
    }
    Ok(())
}

#[test]
fn migration_completion_requires_the_owned_account_directory_and_preserved_original() -> Result<()>
{
    let dir = tempfile::tempdir()?;
    let root = dir.path().canonicalize()?;
    let original = operation(&root)?;
    std::fs::create_dir_all(root.join("accounts").join(&original.account))?;
    let completed = receipt(&original, HostMigrationOutcome::Completed);
    for method in [HOST_MIGRATION_PROFILE_METHOD, HOST_MIGRATION_RESULT_METHOD] {
        validate_terminal_receipt(&completed, &original, method)?;
    }
    let baseline = serde_json::to_value(completed)?;
    for (pointer, value) in [
        ("/operation_id", json!("different")),
        ("/fingerprint", json!("0".repeat(64))),
        (
            "/identity",
            json!({"kind":"bound","account_id":"synthetic","session_sha256":"synthetic"}),
        ),
        ("/details/state", json!("pending")),
        ("/details/account", json!("different")),
        ("/details/dir", json!(root)),
        ("/details/original_preserved", json!(false)),
    ] {
        let mut changed = baseline.clone();
        *changed
            .pointer_mut(pointer)
            .context("synthetic receipt field")? = value;
        assert!(
            validate_terminal_receipt(
                &serde_json::from_value(changed)?,
                &original,
                HOST_MIGRATION_RESULT_METHOD
            )
            .is_err(),
            "accepted changed migration field {pointer}"
        );
    }
    let legacy = receipt(&original, HostMigrationOutcome::AlreadyMigrated);
    validate_terminal_receipt(&legacy, &original, HOST_MIGRATION_PROFILE_METHOD)?;
    assert!(validate_terminal_receipt(&legacy, &original, HOST_MIGRATION_RESULT_METHOD).is_err());
    let mut unknown = receipt(&original, HostMigrationOutcome::Unknown);
    unknown.details = json!({});
    assert!(validate_terminal_receipt(&unknown, &original, HOST_MIGRATION_PROFILE_METHOD).is_err());
    Ok(())
}

#[test]
fn migration_responses_keep_unknown_queries_separate_from_terminal_receipts() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path().canonicalize()?;
    let original = operation(&root)?;
    std::fs::create_dir_all(root.join("accounts").join(&original.account))?;
    for outcome in [
        HostMigrationOutcome::Completed,
        HostMigrationOutcome::AlreadyMigrated,
        HostMigrationOutcome::Unknown,
    ] {
        let request = request(&original, HOST_MIGRATION_PROFILE_METHOD)?;
        let baseline = response(&original, outcome);
        validate_response(
            serde_json::from_value(baseline.clone())?,
            &request,
            &root,
            42,
            &original,
        )?;
        let mut wrong_exit = baseline;
        wrong_exit["exit"] = json!(99);
        assert!(validate_response(
            serde_json::from_value(wrong_exit)?,
            &request,
            &root,
            42,
            &original
        )
        .is_err());
    }
    let query = request(&original, HOST_MIGRATION_RESULT_METHOD)?;
    let baseline = response(&original, HostMigrationOutcome::Unknown);
    for (pointer, value) in [
        ("/v", json!(2)),
        ("/id", json!("different")),
        ("/pid", json!(43)),
        ("/bin", json!("different")),
        ("/operation_id", json!("different")),
        ("/idempotency_key", json!("different")),
        ("/envelope/command", json!("different")),
        ("/envelope/details", json!({})),
        ("/envelope/actions", json!(["unexpected"])),
        ("/envelope/errors", json!(["synthetic"])),
        ("/envelope/items/0/value", json!("false")),
        ("/envelope/items/1/status", json!("ok")),
        ("/envelope/summary/operation_id", json!("different")),
        ("/envelope/summary/fingerprint", json!("0".repeat(64))),
        ("/envelope/summary/details", json!({})),
        ("/ok", json!(true)),
        ("/code", json!(null)),
        ("/envelope/status", json!("ok")),
    ] {
        let mut changed = baseline.clone();
        *changed
            .pointer_mut(pointer)
            .context("synthetic response field")? = value;
        assert!(
            validate_response(
                serde_json::from_value(changed)?,
                &query,
                &root,
                42,
                &original
            )
            .is_err(),
            "accepted changed migration response {pointer}"
        );
    }
    std::fs::write(
        root.join("session.json"),
        br#"{"user":"synthetic-changed-user"}"#,
    )?;
    assert!(validate_response(
        serde_json::from_value(baseline)?,
        &query,
        &root,
        42,
        &original
    )
    .is_err());
    Ok(())
}

#[test]
fn schema_rejection_requires_exact_operation_and_transport_binding() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path().canonicalize()?;
    let original = operation(&root)?;
    let mut rejected = response(&original, HostMigrationOutcome::Unknown);
    rejected["exit"] = json!(1);
    rejected["code"] = json!("migration_schema_rejected");
    rejected["envelope"]["summary"] = serde_json::to_value(&original)?;
    for method in [HOST_MIGRATION_PROFILE_METHOD, HOST_MIGRATION_RESULT_METHOD] {
        validate_response(serde_json::from_value(rejected.clone())?, &request(&original, method)?, &root, 42, &original)?;
    }
    for (pointer, value) in [
        ("/v", json!(999)), ("/id", json!("other")), ("/pid", json!(43)),
        ("/bin", json!("other")), ("/operation_id", json!("other")),
        ("/idempotency_key", json!("other")), ("/data_dir", Value::Null),
        ("/ok", json!(true)), ("/exit", json!(2)), ("/error", json!("untrusted")),
        ("/code", json!("migration_outcome_unknown")),
        ("/envelope/status", json!("ok")), ("/envelope/command", json!("migrate")),
        ("/envelope/items/0/value", json!("false")),
        ("/envelope/items/1/value", json!("true")),
        ("/envelope/summary/operation_id", json!("other")),
        ("/envelope/summary/key", json!("other")),
        ("/envelope/summary/fingerprint", json!("other")),
        ("/envelope/summary/source_id", json!("b".repeat(64))),
        ("/envelope/summary/account", json!("other")),
        ("/envelope/summary/schema_version", json!(99)),
    ] {
        let mut changed = rejected.clone();
        if pointer == "/error" { changed["error"] = value; }
        else { *changed.pointer_mut(pointer).context("missing rejection fixture field")? = value; }
        assert!(validate_response(serde_json::from_value(changed)?,
            &request(&original, HOST_MIGRATION_PROFILE_METHOD)?, &root, 42, &original).is_err(), "{pointer}");
    }
    let mut unknown_field = rejected.clone();
    unknown_field["envelope"]["summary"]["outcome"] = json!("completed");
    assert!(validate_response(serde_json::from_value(unknown_field)?,
        &request(&original, HOST_MIGRATION_PROFILE_METHOD)?, &root, 42, &original).is_err());
    Ok(())
}

#[test]
fn rejected_operation_persists_separately_from_success_receipts() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let original = operation(&dir.path().canonicalize()?)?;
    let saved = Original {
        operation: original.clone(), token: "synthetic-token".into(), coordinator: "synthetic-owner".into(),
        was_serving: true, store_ready: true, sent: true, finished: true,
        terminal_receipt: None, schema_rejection: Some(original.clone()),
    };
    let path = dir.path().join("rejected.json");
    let bytes = serde_json::to_vec(&saved)?;
    std::fs::write(&path, &bytes)?;
    let (read, _) = read_original(&path)?.context("missing rejection")?;
    assert!(read.finished && read.sent && read.terminal_receipt.is_none());
    assert!(read.schema_rejection.as_ref() == Some(&original));
    assert_eq!(std::fs::read(path)?, bytes);
    let envelope = rejection_envelope();
    assert!(matches!(envelope.status, Status::Fail));
    assert_eq!(envelope.summary["code"], "migration_schema_rejected");
    assert!(!envelope.errors.is_empty());
    Ok(())
}
