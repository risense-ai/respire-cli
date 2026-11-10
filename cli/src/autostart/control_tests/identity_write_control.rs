//! Local synthetic receipts and recovery files; never launch the identity transaction.
use super::*;
use serde_json::Value;

fn original(profile: &Path) -> Original {
    Original {
        schema_version: HOST_IDENTITY_WRITE_SCHEMA_V,
        root: profile.to_path_buf(),
        profile: profile.to_path_buf(),
        operation_id: "9c63f43a-a7bc-4820-92c1-ce966406c087".into(),
        key: "9c63f43a-a7bc-4820-92c1-ce966406c087".into(),
        source_identity: HostAuthIdentity::Absent,
        operation: HostIdentityWriteOperation::Logout { full: false },
        token: "synthetic-token-not-a-credential".into(),
        coordinator: "synthetic-coordinator".into(),
        was_serving: false,
        store_ready: false,
        sent: false,
    }
}

fn request(original: &Original) -> Result<RpcRequest> {
    Ok(serde_json::from_value(
        json!({"v":1,"id":"identity-request","method":"control.identity.write_result",
        "args":[],"operation_id":original.operation_id,"idempotency_key":original.key}),
    )?)
}

fn response(
    original: &Original,
    profile: &Path,
    outcome: HostIdentityWriteOutcome,
) -> Result<Value> {
    let (ok, exit, status, code) = match outcome {
        HostIdentityWriteOutcome::Committed => (true, 0, "ok", None),
        HostIdentityWriteOutcome::Pending => (true, 0, "pending", None),
        HostIdentityWriteOutcome::Unknown => {
            (false, 2, "fail", Some("identity_write_outcome_unknown"))
        }
    };
    Ok(
        json!({"v":1,"id":"identity-request","operation_id":original.operation_id,"idempotency_key":original.key,
        "ok":ok,"exit":exit,"code":code,"bin":"rsrs-runtime","pid":42,"data_dir":profile,
        "envelope":{"command":"identity-write","status":status,"summary":{
            "operation_id":original.operation_id,"fingerprint":original.fingerprint()?,"operation":original.operation,
            "outcome":outcome,"path":profile.join("session.json"),"session_found":!matches!(original.source_identity, HostAuthIdentity::Absent),
            "session_sha256":null,"identity":{"kind":"absent"},"revoke":null},
            "items":[{"name":"control_ready","status":"ok","value":"true"},
                     {"name":"store_ready","status":"skip","value":"false"}],
            "actions":[],"errors":[],"details":null}}),
    )
}

#[test]
fn recovery_records_are_bounded_read_only_and_keep_the_original_operation() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let profile = dir.path().canonicalize()?;
    let file = profile.join("identity-write.json");
    assert!(read_original(&file)?.is_none());
    let mut context = original(&profile);
    let fingerprint = context.fingerprint()?;
    context.sent = true;
    context.token = "different-synthetic-token".into();
    assert_eq!(
        context.fingerprint()?,
        fingerprint,
        "transport state cannot change intent"
    );
    let recovery = context.recovery();
    assert!(recovery.query_only);
    assert_eq!(recovery.operation_id, context.operation_id);
    assert_eq!(recovery.key, context.key);
    assert_eq!(recovery.profile, profile);
    assert!(matches!(
        recovery.operation,
        HostIdentityWriteOperation::Logout { full: false }
    ));
    assert_eq!(format!("{recovery:?}"), recovery.to_string());
    assert!(!recovery.to_string().contains("different-synthetic-token"));
    context.operation = HostIdentityWriteOperation::Logout { full: true };
    assert_ne!(context.fingerprint()?, fingerprint);
    let bytes = serde_json::to_vec(&context)?;
    std::fs::write(&file, &bytes)?;
    let (loaded, digest) = read_original(&file)?.context("saved recovery context")?;
    assert_eq!(loaded.operation_id, context.operation_id);
    assert_eq!(digest, super::super::hash(&bytes));
    assert_eq!(std::fs::read(&file)?, bytes);
    std::fs::write(&file, b"not-json")?;
    assert!(read_original(&file).is_err());
    assert_eq!(std::fs::read(&file)?, b"not-json");

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
    std::fs::write(&file, &at_limit)?;
    assert!(read_original(&file)?.is_some());
    assert_eq!(std::fs::read(&file)?, at_limit);
    bounded["token"] = json!("x".repeat(bound - overhead + 1));
    let oversized = serde_json::to_vec(&bounded)?;
    assert_eq!(oversized.len(), bound + 1);
    let _: Original = serde_json::from_slice(&oversized)?;
    std::fs::write(&file, &oversized)?;
    let error = read_original(&file)
        .err()
        .context("oversized valid recovery record must be rejected")?;
    assert_eq!(
        error.to_string(),
        "identity recovery context is not a bounded file"
    );
    assert_eq!(std::fs::read(&file)?, oversized);
    let mut extra = serde_json::to_value(&context)?;
    extra["unexpected"] = json!(true);
    std::fs::write(&file, serde_json::to_vec(&extra)?)?;
    assert!(read_original(&file).is_err());
    assert!(read_original(&profile).is_err());
    #[cfg(unix)]
    {
        let link = profile.join("linked.json");
        // A valid direct target isolates link rejection from JSON/size rejection.
        std::fs::write(&file, &bytes)?;
        assert!(read_original(&file)?.is_some());
        std::os::unix::fs::symlink(&file, &link)?;
        let error = read_original(&link)
            .err()
            .context("symlink to valid recovery record must be rejected")?;
        assert_eq!(error.to_string(), "identity recovery path is a symlink");
        assert_eq!(std::fs::read(&file)?, bytes);
    }
    assert_eq!(
        account(&HostAuthIdentity::Absent, &profile),
        super::super::hash(profile.display().to_string().as_bytes())
    );
    let bound = HostAuthIdentity::Bound {
        account_id: "synthetic-account".into(),
        session_sha256: "a".repeat(64),
    };
    assert_eq!(account(&bound, &profile), "synthetic-account");
    Ok(())
}

#[test]
fn absent_identity_receipts_preserve_committed_pending_and_unknown_outcomes() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let profile = dir.path().canonicalize()?;
    let original = original(&profile);
    let request = request(&original)?;
    for outcome in [
        HostIdentityWriteOutcome::Committed,
        HostIdentityWriteOutcome::Pending,
        HostIdentityWriteOutcome::Unknown,
    ] {
        let baseline = response(&original, &profile, outcome)?;
        validate_response(
            serde_json::from_value(baseline.clone())?,
            &request,
            &profile,
            42,
            &original,
        )?;
        let mut changed = baseline;
        changed["exit"] = json!(99);
        assert!(validate_response(
            serde_json::from_value(changed)?,
            &request,
            &profile,
            42,
            &original
        )
        .is_err());
    }
    Ok(())
}

#[test]
fn identity_receipts_reject_changed_context_and_stale_local_identity() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let profile = dir.path().canonicalize()?;
    let original = original(&profile);
    let request = request(&original)?;
    let baseline = response(&original, &profile, HostIdentityWriteOutcome::Committed)?;
    for (pointer, value) in [
        ("/v", json!(2)),
        ("/id", json!("different")),
        ("/pid", json!(43)),
        ("/bin", json!("different")),
        ("/operation_id", json!("different")),
        ("/idempotency_key", json!("different")),
        ("/envelope/command", json!("different")),
        ("/envelope/details", json!({})),
        ("/envelope/items/0/value", json!("false")),
        ("/envelope/items/1/status", json!("ok")),
        ("/envelope/summary/operation_id", json!("different")),
        ("/envelope/summary/fingerprint", json!("0".repeat(64))),
        ("/envelope/summary/operation/full", json!(true)),
        ("/envelope/summary/path", json!(profile.join("other.json"))),
        ("/envelope/summary/session_found", json!(true)),
        ("/envelope/summary/session_sha256", json!("0".repeat(64))),
        ("/envelope/status", json!("pending")),
        ("/envelope/errors", json!(["synthetic"])),
    ] {
        let mut changed = baseline.clone();
        *changed.pointer_mut(pointer).context("fixture field")? = value;
        assert!(
            validate_response(
                serde_json::from_value(changed)?,
                &request,
                &profile,
                42,
                &original
            )
            .is_err(),
            "accepted changed field {pointer}"
        );
    }
    std::fs::write(
        profile.join("session.json"),
        br#"{"user":"synthetic-user"}"#,
    )?;
    assert!(validate_response(
        serde_json::from_value(baseline)?,
        &request,
        &profile,
        42,
        &original
    )
    .is_err());
    Ok(())
}

#[test]
fn full_logout_and_revoke_receipts_match_the_resulting_local_session() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let profile = dir.path().canonicalize()?;
    let mut original = original(&profile);
    original.source_identity = HostAuthIdentity::Bound {
        account_id: "a".repeat(64),
        session_sha256: "b".repeat(64),
    };
    original.operation = HostIdentityWriteOperation::Logout { full: true };
    let request = request(&original)?;
    let full = response(&original, &profile, HostIdentityWriteOutcome::Committed)?;
    validate_response(
        serde_json::from_value(full)?,
        &request,
        &profile,
        42,
        &original,
    )?;
    let mut soft = original;
    soft.operation = HostIdentityWriteOperation::Logout { full: false };
    assert!(validate_response(
        serde_json::from_value(response(
            &soft,
            &profile,
            HostIdentityWriteOutcome::Committed
        )?)?,
        &request,
        &profile,
        42,
        &soft
    )
    .is_err());
    std::fs::write(
        profile.join("session.json"),
        br#"{"user":"synthetic-user"}"#,
    )?;
    soft.source_identity = super::super::control::identity(&profile)?;
    let session = "c432d4df-0846-4d1d-9d26-b9eb3f23612b";
    soft.operation = HostIdentityWriteOperation::SessionRevoke {
        session_id: session.into(),
    };
    let mut revoke = response(&soft, &profile, HostIdentityWriteOutcome::Committed)?;
    revoke["envelope"]["summary"]["identity"] = serde_json::to_value(&soft.source_identity)?;
    let digest = match &soft.source_identity {
        HostAuthIdentity::Bound { session_sha256, .. } => session_sha256.clone(),
        _ => anyhow::bail!("synthetic bound session expected"),
    };
    revoke["envelope"]["summary"]["session_sha256"] = json!(digest);
    revoke["envelope"]["summary"]["revoke"] = json!({"revoked":true,"session_id":session});
    validate_response(
        serde_json::from_value(revoke.clone())?,
        &request,
        &profile,
        42,
        &soft,
    )?;
    revoke["envelope"]["summary"]["revoke"]["session_id"] =
        json!("c432d4df-0846-4d1d-9d26-b9eb3f23612c");
    assert!(validate_response(
        serde_json::from_value(revoke)?,
        &request,
        &profile,
        42,
        &soft
    )
    .is_err());
    Ok(())
}
