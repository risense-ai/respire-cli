//! Pure response-validator inputs only. These do not attest a Runtime operation,
//! create a recovery journal, or authorize any restore/replay/compensation.
use super::*;
use respire_commands::output::Item;
use serde_json::json;

fn operation(root: &Path) -> Result<SnapshotOperation> {
    let binding = ControlBinding {
        installation_root: root.to_path_buf(),
        profile: root.to_path_buf(),
        launch_id: uuid::Uuid::new_v4().to_string(),
        expected_account_id: Some("a".repeat(64)),
    };
    let mut original = Params {
        schema_version: MAINTENANCE_CONTROL_SCHEMA_V,
        binding,
        operation_id: uuid::Uuid::new_v4().to_string(),
        request_fingerprint: String::new(),
        sync_generation: 7,
        snapshot_id: "b".repeat(32),
        action: Action::Restore,
    };
    original.request_fingerprint = SnapshotOperation::fingerprint(
        &original.binding,
        original.sync_generation,
        &original.snapshot_id,
    )?;
    SnapshotOperation::from_original(original)
}

fn response(operation: &SnapshotOperation, request: &RpcRequest) -> RpcResponse<ResultEnvelope> {
    RpcResponse {
        v: request.v,
        id: request.id.clone(),
        operation_id: request.operation_id.clone(),
        scope: None,
        idempotency_key: request.idempotency_key.clone(),
        ok: true,
        exit: 0,
        bin: "rsrs-runtime".into(),
        error: None,
        code: None,
        web_url: None,
        pid: Some(123),
        data_dir: Some(operation.original.binding.profile.display().to_string()),
        envelope: Some(ResultEnvelope::new(
            "snapshot",
            Status::Ok,
            json!(Receipt {
                operation_id: operation.original.operation_id.clone(),
                request_fingerprint: operation.original.request_fingerprint.clone(),
                snapshot_id: operation.original.snapshot_id.clone(),
                state: State::Unknown,
                before_restore: None,
                sync_quarantined: None,
                cleanup_pending: false,
                cleanup_warning: None,
            }),
            vec![
                Item::new("control_ready", Status::Ok, "true"),
                Item::new("store_ready", Status::Skip, "false"),
            ],
        )),
    }
}

#[test]
fn snapshot_diagnostics_are_allowlisted_without_confirming_an_outcome() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let operation = operation(&directory.path().canonicalize()?)?;
    let original = serde_json::to_value(operation.original())?;
    let request = operation.request(operation.original.binding.clone(), Action::Restore)?;
    let reasons = [
        "snapshot witness checkpoint is unverifiable; diagnostic copy cannot be a restore target",
        "snapshot witness checkpoint mismatch or missing checkpoint",
        "snapshot witness checkpoint exists without a witness schema",
        "unrecognized remote diagnostic with synthetic private data",
    ];
    for (index, reason) in reasons.into_iter().enumerate() {
        let mut rejected = response(&operation, &request);
        rejected.ok = false;
        rejected.exit = 2;
        rejected.code = Some("snapshot_outcome_unknown".into());
        let remote = format!("synthetic-private-prefix: {reason}");
        rejected.error = Some(remote.clone());
        let envelope = rejected.envelope.as_mut().unwrap();
        envelope.status = Status::Fail;
        envelope.errors = vec![remote];
        let error = operation
            .validate_response(rejected.clone(), &request, 123, false)
            .unwrap_err();
        let failure = error
            .downcast_ref::<SnapshotRemoteFailure>()
            .context("typed rejection missing")?;
        assert_eq!(failure.code.as_deref(), Some("snapshot_outcome_unknown"));
        assert_eq!(failure.exit, 2);
        assert_eq!(failure.validation_reason, (index < 3).then_some(reason));
        assert!(!format!("{error:#}").contains("synthetic-private-prefix"));
        if index == 3 {
            assert!(!format!("{error:#}").contains(reason));
        }
        // Even an allowlisted message is suppressed when its envelope does not
        // exactly agree, or when it refers to a query rather than this Restore.
        rejected.envelope.as_mut().unwrap().errors.clear();
        assert_eq!(
            operation.restore_validation_reason(&rejected, &request),
            None
        );
        rejected.envelope.as_mut().unwrap().errors = vec![rejected.error.clone().unwrap()];
        let query = operation.request(operation.original.binding.clone(), Action::Query)?;
        assert_eq!(operation.restore_validation_reason(&rejected, &query), None);
        let mut changed = request.clone();
        let mut params: Params = serde_json::from_str(&changed.args[0])?;
        params.operation_id = uuid::Uuid::new_v4().to_string();
        changed.args[0] = serde_json::to_string(&params)?;
        assert_eq!(
            operation.restore_validation_reason(&rejected, &changed),
            None
        );
    }
    assert_eq!(serde_json::to_value(operation.original())?, original);
    Ok(())
}

#[test]
fn snapshot_result_validation_preserves_unknown_and_terminal_cleanup_boundaries() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let operation = operation(&directory.path().canonicalize()?)?;
    let request = operation.request(operation.original.binding.clone(), Action::Query)?;
    let unknown = response(&operation, &request);
    let envelope = operation.validate_response(unknown.clone(), &request, 123, false)?;
    let receipt: Receipt = serde_json::from_value(envelope.summary)?;
    assert_eq!(receipt.state, State::Unknown);
    assert!(!receipt.cleanup_pending && receipt.before_restore.is_none());
    let mut invalid = unknown.clone();
    invalid.envelope.as_mut().unwrap().summary["sync_quarantined"] = json!(true);
    assert_eq!(
        operation
            .validate_response(invalid, &request, 123, false)
            .unwrap_err()
            .to_string(),
        "inconsistent snapshot receipt state"
    );

    let mut terminal = unknown;
    let envelope = terminal.envelope.as_mut().unwrap();
    envelope.status = Status::Warn;
    envelope.summary["state"] = json!("released");
    envelope.summary["before_restore"] = json!("c".repeat(32));
    envelope.summary["sync_quarantined"] = json!(true);
    envelope.summary["cleanup_pending"] = json!(true);
    envelope.summary["cleanup_warning"] = json!("synthetic cleanup pending");
    envelope.errors = vec!["synthetic cleanup pending".into()];
    let accepted = operation.validate_response(terminal.clone(), &request, 123, false)?;
    let receipt: Receipt = serde_json::from_value(accepted.summary)?;
    assert_eq!(receipt.state, State::Released);
    assert!(receipt.cleanup_pending);
    assert_eq!(
        receipt.cleanup_warning.as_deref(),
        Some("synthetic cleanup pending")
    );
    let mut invalid = terminal.clone();
    invalid.envelope.as_mut().unwrap().summary["cleanup_pending"] = json!(false);
    assert_eq!(
        operation
            .validate_response(invalid, &request, 123, false)
            .unwrap_err()
            .to_string(),
        "snapshot cleanup warning lacks pending cleanup"
    );
    terminal.envelope.as_mut().unwrap().errors = vec!["different warning".into()];
    assert_eq!(
        operation
            .validate_response(terminal, &request, 123, false)
            .unwrap_err()
            .to_string(),
        "snapshot envelope and receipt disagree"
    );
    Ok(())
}
