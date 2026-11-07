//! Synthetic metadata receipts and recovery files. No store, keys or Runtime are opened.
use super::*;
use serde_json::{json, Value};

fn operation(root: &Path, intent: HostMetadataIntent) -> Result<HostMetadataOperation> {
    let mut original = HostMetadataOperation {
        schema_version: HOST_METADATA_SCHEMA_V,
        operation_id: "9aebc466-8279-46fc-8bcb-4db6e054b886".into(),
        key: "9aebc466-8279-46fc-8bcb-4db6e054b886".into(),
        installation_root: root.to_path_buf(),
        profile: root.to_path_buf(),
        identity: metadata_identity(root, super::super::hash)?,
        intent,
        fingerprint: String::new(),
    };
    original.fingerprint = super::super::hash(&original.fingerprint_bytes()?);
    Ok(original)
}

fn receipt(
    original: &HostMetadataOperation,
    outcome: HostMetadataOutcome,
) -> Result<HostMetadataResult> {
    let details = if outcome == HostMetadataOutcome::Unknown {
        Value::Null
    } else {
        match &original.intent {
            HostMetadataIntent::Disable => json!({"enabled":false,"metadata_retained":true,
                "sync_isolation_retained":true,"mode":"isolated"}),
            HostMetadataIntent::Enable {
                mode,
                deployment_review,
            } => json!({"receipt":{"enabled":true,
                "deployment":{"mode":mode},"backup":{}},"deployment_review":deployment_review,
                "deployment_assurance":"operator_attestation_only","old_client_access_enforced":false}),
        }
    };
    Ok(HostMetadataResult {
        original: original.clone(),
        outcome,
        details,
    })
}

#[test]
fn metadata_recovery_records_are_bounded_and_preserve_the_saved_intent() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path().canonicalize()?;
    let path = root.join("metadata.json");
    assert!(read_original(&path)?.is_none());
    let original = Original {
        operation: operation(&root, HostMetadataIntent::Disable)?,
        token: "synthetic-token".into(),
        coordinator: "synthetic-coordinator".into(),
        was_serving: false,
        store_ready: false,
        sent: true,
        finished: false,
    };
    let bytes = serde_json::to_vec(&original)?;
    std::fs::write(&path, &bytes)?;
    let (loaded, digest) = read_original(&path)?.context("saved metadata context")?;
    assert!(loaded.sent && !loaded.finished);
    assert_eq!(loaded.operation.fingerprint, original.operation.fingerprint);
    assert_eq!(digest, super::super::hash(&bytes));
    assert_eq!(std::fs::read(&path)?, bytes);
    std::fs::write(&path, b"invalid JSON")?;
    assert!(read_original(&path).is_err());
    assert_eq!(std::fs::read(&path)?, b"invalid JSON");

    // Keep the schema valid so only the file-size boundary can reject this record.
    let bound = 64 * 1024;
    let mut bounded = serde_json::to_value(&original)?;
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
    assert_eq!(error.to_string(), "invalid metadata recovery metadata");
    assert_eq!(std::fs::read(&path)?, oversized);
    let mut extra = serde_json::to_value(&original)?;
    extra["unexpected"] = json!(true);
    std::fs::write(&path, serde_json::to_vec(&extra)?)?;
    assert!(read_original(&path).is_err());
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
        assert_eq!(error.to_string(), "metadata recovery path is a symlink");
        assert_eq!(std::fs::read(&path)?, bytes);
    }
    assert!(canonical_id(&original.operation.operation_id));
    assert!(!canonical_id("9aebc466-8279-56fc-8bcb-4db6e054b886"));
    assert!(!canonical_id("invalid"));
    Ok(())
}

#[test]
fn metadata_output_requires_a_committed_receipt_and_retains_operator_assurance_limits() -> Result<()>
{
    let dir = tempfile::tempdir()?;
    let root = dir.path().canonicalize()?;
    let intents = [
        HostMetadataIntent::Disable,
        HostMetadataIntent::Enable {
            mode: "isolated".into(),
            deployment_review: None,
        },
        HostMetadataIntent::Enable {
            mode: "controlled_writers".into(),
            deployment_review: Some(MetadataDeploymentReview {
                operator: "synthetic-operator".into(),
                upgraded_writers: "synthetic-review".into(),
                disconnected_old_clients: "synthetic-review".into(),
                reconciled_offline_writes: "synthetic-review".into(),
            }),
        },
    ];
    for intent in intents {
        let original = operation(&root, intent)?;
        let receipt = receipt(&original, HostMetadataOutcome::Committed)?;
        let envelope = metadata_result(&receipt)?;
        let enabled = matches!(original.intent, HostMetadataIntent::Enable { .. });
        assert_eq!(envelope.command, "metadata");
        assert!(matches!(envelope.status, Status::Ok));
        assert_eq!(
            envelope.summary,
            json!({"action":if enabled {"enabled"} else {"disabled"},"enabled":enabled})
        );
        assert_eq!(envelope.details, receipt.details);
        let changes = if enabled {
            vec![
                ("/receipt/enabled", json!(false)),
                ("/receipt/deployment/mode", json!("different")),
                ("/receipt/backup", json!(null)),
                ("/deployment_review", json!({"unexpected":true})),
                ("/deployment_assurance", json!("verified")),
                ("/old_client_access_enforced", json!(true)),
            ]
        } else {
            vec![
                ("/enabled", json!(true)),
                ("/metadata_retained", json!(null)),
                ("/sync_isolation_retained", json!(false)),
                ("/mode", json!("off")),
            ]
        };
        for (pointer, value) in changes {
            let mut changed = serde_json::to_value(&receipt)?;
            *changed["details"]
                .pointer_mut(pointer)
                .context("synthetic metadata detail")? = value;
            assert!(
                metadata_result(&serde_json::from_value(changed)?).is_err(),
                "accepted changed detail {pointer}"
            );
        }
        assert!(metadata_result(&self::receipt(&original, HostMetadataOutcome::Unknown)?).is_err());
    }
    Ok(())
}

#[test]
fn metadata_responses_bind_original_intent_and_keep_unknown_outcomes_uncommitted() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path().canonicalize()?;
    let original = operation(&root, HostMetadataIntent::Disable)?;
    let request: RpcRequest = serde_json::from_value(
        json!({"v":1,"id":"metadata-request","method":HOST_METADATA_RESULT_METHOD,
        "args":[],"operation_id":original.operation_id,"idempotency_key":original.key}),
    )?;
    for outcome in [HostMetadataOutcome::Committed, HostMetadataOutcome::Unknown] {
        let unknown = outcome == HostMetadataOutcome::Unknown;
        let baseline = json!({"v":1,"id":"metadata-request","pid":42,"bin":"rsrs-runtime","data_dir":root,
            "operation_id":original.operation_id,"idempotency_key":original.key,"ok":!unknown,"exit":if unknown {2} else {0},
            "code":if unknown {Some("metadata_outcome_unknown")} else {None},
            "envelope":{"command":"metadata-control","status":if unknown {"fail"} else {"ok"},
                "summary":receipt(&original,outcome)?,"details":null,"actions":[],"errors":[],"related":[],
                "items":[{"name":"control_ready","status":"ok","value":"true"},
                    {"name":"store_ready","status":"skip","value":"false"}]}});
        validate_response(
            serde_json::from_value(baseline.clone())?,
            &request,
            &root,
            42,
            &original,
        )?;
        for (pointer, value) in [
            ("/v", json!(2)),
            ("/id", json!("different")),
            ("/pid", json!(43)),
            ("/bin", json!("different")),
            ("/operation_id", json!("different")),
            ("/idempotency_key", json!("different")),
            ("/exit", json!(99)),
            ("/envelope/command", json!("different")),
            ("/envelope/details", json!({})),
            ("/envelope/actions", json!(["unexpected"])),
            ("/envelope/errors", json!(["synthetic"])),
            ("/envelope/items/0/value", json!("false")),
            ("/envelope/items/1/status", json!("ok")),
            (
                "/envelope/summary/original/fingerprint",
                json!("0".repeat(64)),
            ),
        ] {
            let mut changed = baseline.clone();
            *changed
                .pointer_mut(pointer)
                .context("synthetic metadata response field")? = value;
            assert!(
                validate_response(
                    serde_json::from_value(changed)?,
                    &request,
                    &root,
                    42,
                    &original
                )
                .is_err(),
                "accepted changed metadata response {pointer}"
            );
        }
        let mut changed = baseline.clone();
        changed["envelope"]["summary"]["details"] = json!({"unexpected":true});
        assert!(validate_response(
            serde_json::from_value(changed)?,
            &request,
            &root,
            42,
            &original
        )
        .is_err());
        std::fs::write(
            root.join("session.json"),
            br#"{"user":"synthetic-changed-user"}"#,
        )?;
        assert!(validate_response(
            serde_json::from_value(baseline)?,
            &request,
            &root,
            42,
            &original
        )
        .is_err());
        std::fs::remove_file(root.join("session.json"))?;
    }
    Ok(())
}
