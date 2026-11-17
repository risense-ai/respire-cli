//! One reviewed agent setting, using the existing maintenance marker and config CAS.
use std::time::Duration;
use anyhow::{Context, Result};
use respire_commands::output::{ResultEnvelope, Status};
use respire_protocol::config_control::*;
use respire_protocol::metadata_control::metadata_identity;
use respire_protocol::RpcRequest;

fn host_config_preflight(root: &std::path::Path, profile: &std::path::Path) -> anyhow::Result<()> {
    use serde_json::Value;
    let read = |path: std::path::PathBuf| -> anyhow::Result<Option<Value>> {
        respire_client_host::config::normalize_control_path(&path)?;
        match std::fs::read(path) {
            Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    };
    if let Some(journal) = read(root.join(".login-recovery.json"))? {
        anyhow::ensure!(journal["schema_version"] == 2 && journal.get("active").is_some_and(Value::is_null),
            "auth_recovery_pending: finish account recovery before changing agent configuration");
    }
    // These records only exclude an active restore; they never authorize recovery or database access.
    respire_client_host::config::normalize_control_path(&profile.join(".snapshot-maintenance.json"))?;
    anyhow::ensure!(!profile.join(".snapshot-maintenance.json").try_exists()?,
        "snapshot maintenance blocks agent configuration; finish snapshot recovery first");
    if let Some(journal) = read(profile.join(".snapshot-recovery.json"))? {
        anyhow::ensure!(journal["schema_version"] == 1
            && matches!(journal["phase"].as_str(), Some("verified" | "released" | "rolled_back")),
            "snapshot recovery blocks agent configuration; finish snapshot recovery first");
    }
    Ok(())
}

fn validate_host_agent_config(intent: &AgentConfigIntent, profile: &std::path::Path) -> Result<()> {
    let agent = crate::client_config::read_agent_config_for_write(profile)?;
    anyhow::ensure!(!(agent["readonly_team"] == true
        && intent.key.trim() == "readonly" && intent.value() == false),
        "this space is read-only - you cannot lift read-only yourself");
    if matches!(intent.key.trim(), "read_heat" | "recall_fusion") {
        let candidate = intent.apply(&agent).map_err(anyhow::Error::msg)?;
        core_candidate(&candidate)?;
    }
    Ok(())
}

fn core_candidate(agent: &serde_json::Value) -> Result<serde_json::Value> {
    if let Some(value) = agent.get("read_heat") {
        anyhow::ensure!(value.is_boolean(), "read_heat must be true or false");
    }
    if let Some(value) = agent.get("recall_fusion") { crate::recall_fusion::validate(value)?; }
    Ok(serde_json::json!({"read_heat":agent.get("read_heat"), "recall_fusion":agent.get("recall_fusion")}))
}

/// Paused rejects new query execution; these counters cover requests admitted before it.
fn wait_core_queries(owner: &crate::net_rpc::Health) -> Result<()> {
    let scope = crate::net_rpc::request_scope(owner)?;
    loop {
        let current = crate::rpc::probe_runtime()?.context("core config owner exited while waiting for queries")?;
        anyhow::ensure!(current.pid == owner.pid && current.process_start_id == owner.process_start_id
            && crate::net_rpc::request_scope(&current)? == scope, "core config owner changed while waiting for queries");
        let mut idle = true;
        for field in ["ordinary_running", "lightweight_running", "queued_or_cancelled_pending_removal", "executing_until_reply"] {
            let count = current.rpc[field].as_u64().with_context(|| format!(
                "core config requires Runtime query occupancy field {field}"))?;
            idle &= count == 0;
        }
        if idle { return Ok(()); }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CoreConfigTransaction {
    scope: Option<respire_protocol::RuntimeRequestScope>,
    revision: u64,
    candidate: serde_json::Value,
    validated: Option<serde_json::Value>,
    apply_sent: bool,
    rollback_sent: bool,
    response: Option<respire_protocol::RpcResponse<ResultEnvelope>>,
}

fn core_exchange(
    maintenance: &mut super::lifecycle::Maintenance,
    profile: &std::path::Path,
    scope: &respire_protocol::RuntimeRequestScope,
    method: &str,
    operation: &str,
    candidate: Option<&serde_json::Value>,
    revision: Option<u64>,
) -> Result<respire_protocol::RpcResponse<ResultEnvelope>> {
    let owner = crate::rpc::probe_runtime()?.context("core config owner is unavailable")?;
    anyhow::ensure!(crate::net_rpc::request_scope(&owner)? == *scope, "core config owner changed");
    let binding = maintenance.auth_launch_binding(profile)?.context("core config lost Paused maintenance")?;
    let mut payload = serde_json::json!({"schema_version":1,"maintenance":binding});
    if let Some(candidate) = candidate { payload["candidate"] = candidate.clone(); }
    if let Some(revision) = revision { payload["expected_revision"] = revision.into(); }
    let request = RpcRequest { v: 1, id: operation.into(), method: method.into(),
        args: vec![serde_json::to_string(&payload)?], scope: Some(scope.clone()),
        operation_id: Some(operation.into()), idempotency_key: Some(operation.into()),
        parent_operation_id: None, queue_wait_ms: None, lifecycle: None };
    let token = respire_client_host::credential::read_token_file(&crate::net_rpc::token_path())?
        .context("core config Runtime bearer token missing")?;
    let response: respire_protocol::RpcResponse<ResultEnvelope> = ureq::AgentBuilder::new()
        .redirects(0).build().post(&format!("{}/api/rpc", crate::net_rpc::rpc_base_url()))
        .set("Authorization", &format!("Bearer {token}"))
        .send_json(serde_json::to_value(&request)?)?.into_json()?;
    anyhow::ensure!(response.v == request.v && response.id == request.id
        && response.exit >= 0 && response.ok == (response.exit == 0)
        && response.code.as_deref() != Some("protocol_version_mismatch")
        && response.scope.as_ref() == Some(scope) && response.pid == Some(owner.pid)
        && response.operation_id.as_deref() == Some(operation)
        && response.idempotency_key.as_deref() == Some(operation)
        && response.data_dir.as_deref().is_some_and(|path| std::path::Path::new(path) == profile),
        "core config response binding mismatch");
    Ok(response)
}

fn core_state(response: &respire_protocol::RpcResponse<ResultEnvelope>, state: &str,
    candidate: Option<&serde_json::Value>, revision: Option<u64>) -> Result<serde_json::Value> {
    anyhow::ensure!(response.ok && response.exit == 0 && response.error.is_none() && response.code.is_none(),
        "core config request rejected: {}", response.error.as_deref().unwrap_or("missing successful response"));
    let envelope = response.envelope.as_ref().context("core config response missing")?;
    let summary = &envelope.summary;
    anyhow::ensure!(matches!(envelope.status, Status::Ok) && envelope.errors.is_empty()
        && summary.as_object().is_some_and(|object| object.len() == 6)
        && summary["state"] == state && summary["revision"].as_u64().is_some()
        && candidate.is_none_or(|candidate| summary["candidate"] == *candidate)
        && revision.is_none_or(|revision| summary["revision"] == revision)
        && summary["applies"] == "next_query"
        && summary["capabilities"] == serde_json::json!({"read_heat_contract":1,"recall_fusion_contract":1})
        && summary["effective"]["read_heat"].is_boolean(), "core config state receipt mismatch");
    crate::recall_fusion::validate(&summary["effective"]["recall_fusion"])?;
    Ok(summary.clone())
}

fn save_core_receipt(record: &mut AgentConfigMaintenance, maintenance: &mut super::lifecycle::Maintenance,
    control: &CoreConfigTransaction, output: ResultEnvelope, outcome: AgentConfigOutcome) -> Result<()> {
    record.receipt = Some(AgentConfigReceipt { review: record.review.clone(), outcome,
        result: serde_json::json!({"output":output,"core_control":control}) });
    maintenance.save_agent_config(record)
}

fn control_core_setting(record: &mut AgentConfigMaintenance, maintenance: &mut super::lifecycle::Maintenance,
    owner: Option<&crate::net_rpc::Health>) -> Result<ResultEnvelope> {
    use respire_client_host::lock::LibraryLock;
    let review = record.review.clone();
    let _root = LibraryLock::acquire(&review.installation_root, Duration::from_secs(15))?;
    let _profile = if review.installation_root == review.profile { None }
        else { Some(LibraryLock::acquire(&review.profile, Duration::from_secs(15))?) };
    host_config_preflight(&review.installation_root, &review.profile)?;
    anyhow::ensure!(!record.sent || record.receipt.is_some(),
        "agent_config_outcome_unknown operation_id={}; no publication receipt; do not replay", review.operation_id);
    if !record.sent {
        if let Some(owner) = owner { wait_core_queries(owner)?; }
        validate_host_agent_config(&review.intent, &review.profile)?;
        let original: serde_json::Value = review.original_config.as_deref().map(serde_json::from_str)
            .transpose()?.unwrap_or_else(|| serde_json::json!({}));
        let candidate = core_candidate(&review.intent.apply(&original).map_err(anyhow::Error::msg)?)?;
        let mut control = CoreConfigTransaction { scope: owner.map(crate::net_rpc::request_scope).transpose()?,
            revision: 0, candidate, validated: None, apply_sent: false, rollback_sent: false, response: None };
        if let Some(scope) = control.scope.as_ref() {
            let current = core_exchange(maintenance, &review.profile, scope, "core_config.read",
                &uuid::Uuid::new_v4().to_string(), None, None)?;
            let current = core_state(&current, "current", None, None)?;
            control.revision = current["revision"].as_u64().context("core revision missing")?;
            let validated = core_exchange(maintenance, &review.profile, scope, "core_config.validate",
                &uuid::Uuid::new_v4().to_string(), Some(&control.candidate), None)?;
            control.validated = Some(core_state(&validated, "validated", Some(&control.candidate), Some(control.revision))?);
        }
        let output = ResultEnvelope::new("agent-config", Status::Ok,
            serde_json::json!({"action":"updated","key":review.intent.key,"value":review.intent.value(),
                "core_application":{"state":"pending","reason":"runtime_not_running","applies":"next_query"}}),
            vec![respire_commands::output::Item::new(&review.intent.key, Status::Ok, &review.intent.raw_value)]);
        let mut preview = record.clone();
        preview.sent = true;
        preview.receipt = Some(AgentConfigReceipt { review: review.clone(), outcome: AgentConfigOutcome::Committed,
            result: serde_json::json!({"output":output,"core_control":control}) });
        maintenance.check_agent_config_record(&preview)?;
        record.sent = true;
        maintenance.save_agent_config(record)?;
        crate::client_config::publish_agent_config(&review, ||
            save_core_receipt(record, maintenance, &control, output.clone(), AgentConfigOutcome::Committed))?;
    }
    let receipt = record.receipt.as_ref().context("core host publication receipt missing")?;
    anyhow::ensure!(receipt.review == review, "core receipt changed original intent");
    let mut control: CoreConfigTransaction = serde_json::from_value(receipt.result["core_control"].clone())?;
    let mut output: ResultEnvelope = serde_json::from_value(receipt.result["output"].clone())?;
    let original: serde_json::Value = review.original_config.as_deref().map(serde_json::from_str)
        .transpose()?.unwrap_or_else(|| serde_json::json!({}));
    anyhow::ensure!(control.candidate == core_candidate(&review.intent.apply(&original).map_err(anyhow::Error::msg)?)?
        && output.command == "agent-config", "core transaction differs from original host intent");
    anyhow::ensure!(receipt.outcome == AgentConfigOutcome::RolledBack || !control.rollback_sent,
        "agent_config_outcome_unknown; rollback has no terminal receipt; do not replay");
    crate::client_config::verify_agent_config_receipt(receipt)?;
    if receipt.outcome == AgentConfigOutcome::RolledBack || control.scope.is_none() { return Ok(output); }
    let scope = control.scope.clone().context("core scope missing")?;
    let current = crate::rpc::probe_runtime()?.context("agent_config_outcome_unknown; original core owner unavailable")?;
    anyhow::ensure!(crate::net_rpc::request_scope(&current)? == scope,
        "agent_config_outcome_unknown; original core owner changed; do not replay");
    if control.response.is_none() {
        let response = if control.apply_sent {
            let operation = respire_commands::runtime_error::OperationContext { scope: scope.clone(),
                operation_id: review.operation_id.clone(), idempotency_key: review.operation_id.clone() };
            let result = crate::net_rpc::rpc_result(&operation)?;
            let state = &result["envelope"]["summary"];
            anyhow::ensure!(matches!(state["state"].as_str(), Some("completed" | "failed"))
                && state["operation_id"] == review.operation_id && state["scope"] == serde_json::to_value(&scope)?,
                "agent_config_outcome_unknown; original core operation has no terminal response; do not replay");
            serde_json::from_value(state["response"].clone())?
        } else {
            control.apply_sent = true;
            save_core_receipt(record, maintenance, &control, output.clone(), AgentConfigOutcome::Committed)?;
            core_exchange(maintenance, &review.profile, &scope, "core_config.apply", &review.operation_id,
                Some(&control.candidate), Some(control.revision)).context(
                    "agent_config_outcome_unknown; query original core operation; do not replay")?
        };
        let response: respire_protocol::RpcResponse<ResultEnvelope> = response;
        anyhow::ensure!(response.v == 1 && response.exit >= 0 && response.ok == (response.exit == 0)
            && response.scope.as_ref() == Some(&scope) && response.id == review.operation_id
            && response.operation_id.as_deref() == Some(review.operation_id.as_str())
            && response.idempotency_key.as_deref() == Some(review.operation_id.as_str()), "core original operation receipt mismatch");
        anyhow::ensure!(response.ok || response.code.as_deref() == Some("core_config_rejected"),
            "agent_config_outcome_unknown; core response does not prove application or rejection; do not replay");
        control.response = Some(response);
        save_core_receipt(record, maintenance, &control, output.clone(), AgentConfigOutcome::Committed)?;
    }
    let response = control.response.clone().context("core application response missing")?;
    if !response.ok {
        control.rollback_sent = true;
        save_core_receipt(record, maintenance, &control, output.clone(), AgentConfigOutcome::Committed)?;
        output.status = Status::Fail;
        output.summary = serde_json::json!({"action":"rolled_back","core_application":{"state":"rejected"}});
        output.items.clear();
        output.errors = vec![response.error.clone().context("core rejection reason missing")?];
        crate::client_config::rollback_agent_config(&review, ||
            save_core_receipt(record, maintenance, &control, output.clone(), AgentConfigOutcome::RolledBack))?;
    } else {
        let revision = control.revision.checked_add(1).context("core revision overflow")?;
        let applied = core_state(&response, "applied", Some(&control.candidate), Some(revision))?;
        let validated = control.validated.as_ref().context("core validation receipt missing")?;
        anyhow::ensure!(applied["effective"] == validated["effective"], "core effective state differs from validation");
        let current = core_exchange(maintenance, &review.profile, &scope, "core_config.read",
            &uuid::Uuid::new_v4().to_string(), None, None)?;
        let current = core_state(&current, "current", Some(&control.candidate), Some(revision))?;
        anyhow::ensure!(current["effective"] == applied["effective"], "core state changed after application");
        output.summary["core_application"] = serde_json::json!({"state":"applied","applies":"next_query",
            "scope":scope,"revision":revision,"effective":applied["effective"]});
        save_core_receipt(record, maintenance, &control, output.clone(), AgentConfigOutcome::Committed)?;
    }
    crate::client_config::verify_agent_config_receipt(record.receipt.as_ref().context("core terminal receipt missing")?)?;
    Ok(output)
}

fn control_host_agent_config(intent: respire_protocol::config_control::AgentConfigIntent) -> anyhow::Result<respire_commands::output::ResultEnvelope> {
    use respire_client_host::lock::LibraryLock;
    let _takeover = crate::runtime_policy::takeover_lock()?;
    let (root, profile) = respire_client_host::config::control_roots()?;
    std::fs::create_dir_all(&root)?;
    std::fs::create_dir_all(&profile)?;
    let root = root.canonicalize()?;
    let profile = profile.canonicalize()?;
    let identity = metadata_identity(&profile, super::hash)?;
    let account = identity.account_id.clone().unwrap_or_else(|| super::hash(profile.display().to_string().as_bytes()));
    let saved = super::lifecycle::pending_agent_config(&root)?;
    let registration = super::read_registration(&root)?;
    let managed = registration.as_ref().filter(|config| config.enabled && !config.manually_stopped);
    let owner = crate::rpc::probe_runtime()?;
    anyhow::ensure!(owner.is_some() || !crate::rpc::endpoint_path().try_exists()?, "agent config owner is not verifiable");
    if let Some(config) = managed {
        super::lifecycle::owned(config)?;
        super::lifecycle::ensure_control_endpoint(config)?;
        anyhow::ensure!(owner.is_some() || !super::super::super::manager::inspect(config)?.running,
            "agent config cannot identify the registered owner");
    }
    let runtime = if owner.is_some() || saved.as_ref().is_some_and(|(record, _, _)| record.was_serving) {
        Some(super::model_control::installed_model_runtime()?)
    } else { None };
    if let (Some(owner), Some((binary, manifest))) = (owner.as_ref(), runtime.as_ref()) {
        super::model_control::verify_model_owner(owner, &root, &profile, managed, binary, manifest, Some(&account))?;
    }
    host_config_preflight(&root, &profile)?;
    let (mut record, mut maintenance) = if let Some((record, token, coordinator)) = saved {
        anyhow::ensure!(record.review.intent == intent && record.review.identity == identity
            && record.review.installation_root == root && record.review.profile == profile,
            "repeat the original agent-config intent and identity; a new operation is not allowed");
        let maintenance = super::lifecycle::resume_agent_config_maintenance(&root, &profile, &token, &coordinator)?;
        (record, maintenance)
    } else {
        validate_host_agent_config(&intent, &profile)?;
        let review = crate::client_config::review_agent_config(intent, root.clone(), profile.clone())?;
        let mut maintenance = super::lifecycle::begin_maintenance_locked()?;
        maintenance.auth_launch_binding(&profile)?.context("agent config requires actual Paused maintenance")?;
        let record = AgentConfigMaintenance { review, was_serving: owner.is_some(),
            store_ready: owner.as_ref().is_some_and(|health| health.store_ready), sent: false, receipt: None };
        maintenance.save_agent_config(&record)?;
        (record, maintenance)
    };
    let operation = record.review.operation_id.clone();
    let core_setting = matches!(record.review.intent.key.trim(), "read_heat" | "recall_fusion");
    let mut finished = false;
    let result = (|| -> Result<ResultEnvelope> {
        maintenance.auth_launch_binding(&profile)?.context("agent config lost its Paused grant")?;
        if core_setting {
            let output = control_core_setting(&mut record, &mut maintenance, owner.as_ref())?;
            if let Some(previous) = owner.as_ref() {
                let current = crate::rpc::probe_runtime()?.context("core config owner exited before completion")?;
                let (binary, manifest) = runtime.as_ref().context("core config Runtime selection missing")?;
                let (selected, selected_manifest) = super::model_control::installed_model_runtime()?;
                anyhow::ensure!(selected == *binary && selected_manifest.version == manifest.version
                    && selected_manifest.sha256.eq_ignore_ascii_case(&manifest.sha256)
                    && current.pid == previous.pid && current.process_start_id == previous.process_start_id
                    && crate::net_rpc::request_scope(&current)? == crate::net_rpc::request_scope(previous)?,
                    "core config owner or Runtime selection changed before completion");
                super::model_control::verify_model_owner(&current, &root, &profile, managed, binary, manifest, Some(&account))?;
            }
            maintenance.finish()?;
            finished = true;
            return Ok(output);
        }
        anyhow::ensure!(!record.sent || record.receipt.is_some(),
            "agent_config_outcome_unknown operation_id={operation}; original O has no receipt; do not replay");
        if record.was_serving { maintenance.check_account_runtime()?; }
        if let Some(owner) = owner.as_ref() { maintenance.drain_runtime(owner)?; }
        anyhow::ensure!(!crate::net_rpc::port_is_open(), "agent config requires a drained Runtime");
        {
            let _root_lock = LibraryLock::acquire(&root, Duration::from_secs(15))?;
            let _profile_lock = if root == profile { None } else { Some(LibraryLock::acquire(&profile, Duration::from_secs(15))?) };
            host_config_preflight(&root, &profile)?;
            if !record.sent {
                anyhow::ensure!(record.receipt.is_none(), "agent config unsent operation has a receipt");
                validate_host_agent_config(&record.review.intent, &profile)?;
                let intent = &record.review.intent;
                let result = ResultEnvelope::new("agent-config", Status::Ok,
                    serde_json::json!({"action":"updated", "key":intent.key, "value":intent.value()}),
                    vec![respire_commands::output::Item::new(&intent.key, Status::Ok, &intent.raw_value)]);
                let receipt = AgentConfigReceipt { review: record.review.clone(), outcome: AgentConfigOutcome::Committed,
                    result: serde_json::to_value(result)? };
                let mut preview = record.clone();
                preview.sent = true;
                preview.receipt = Some(receipt.clone());
                maintenance.check_agent_config_record(&preview)?;
                record.sent = true;
                maintenance.save_agent_config(&record)?;
                crate::client_config::publish_agent_config(&receipt.review, || {
                    record.receipt = Some(receipt.clone());
                    maintenance.save_agent_config(&record)
                })?;
            }
            crate::client_config::verify_agent_config_receipt(record.receipt.as_ref().context("agent config receipt missing")?)?;
        }
        let receipt = record.receipt.as_ref().context("agent config receipt missing")?;
        anyhow::ensure!(receipt.review == record.review, "agent config receipt changed original intent");
        if let Some((binary, manifest)) = runtime.as_ref() {
            let (current_binary, current_manifest) = super::model_control::installed_model_runtime()?;
            anyhow::ensure!(*binary == current_binary && manifest.version == current_manifest.version
                && manifest.sha256.eq_ignore_ascii_case(&current_manifest.sha256), "agent config Runtime selection changed");
            if record.was_serving {
                maintenance.start_account_runtime()?;
                let restored = crate::rpc::probe_runtime()?.context("agent config original owner did not resume")?;
                super::model_control::verify_model_owner(&restored, &root, &profile, managed, binary, manifest, Some(&account))?;
                anyhow::ensure!(!record.store_ready || restored.store_ready || respire_client_host::settings::off_mode()?,
                    "agent config original owner lacks store readiness");
            }
        }
        crate::client_config::verify_agent_config_receipt(receipt)?;
        let result: ResultEnvelope = serde_json::from_value(receipt.result.clone())?;
        anyhow::ensure!(result.command == "agent-config" && matches!(result.status, Status::Ok)
            == (receipt.outcome == AgentConfigOutcome::Committed), "invalid agent config setter receipt");
        if receipt.outcome == AgentConfigOutcome::Committed {
            let intent = &record.review.intent;
            anyhow::ensure!(result.summary == serde_json::json!({"action":"updated", "key":intent.key, "value":intent.value()})
                && result.items.len() == 1 && result.items[0].name == intent.key
                && result.items[0].value == intent.raw_value && matches!(result.items[0].status, Status::Ok)
                && result.details.is_null() && result.errors.is_empty() && result.actions.is_empty() && result.related.is_empty(),
                "agent config result differs from original setter output");
        }
        maintenance.finish()?;
        finished = true;
        Ok(result)
    })();
    if !finished {
        let actual = maintenance.refresh_agent_config()?;
        maintenance.mark(super::lifecycle::Phase::Paused)?;
        if actual.sent && actual.receipt.is_none() {
            return result.map_err(|error| error.context(format!(
                "agent_config_outcome_unknown operation_id={operation}; retain original O; do not replay")));
        }
    }
    if result.is_ok() && finished && record.was_serving && !core_setting { maintenance.finish_handoff()?; }
    result.map_err(|error| error.context(format!("agent config operation_id={operation}; repeat the same command to query original O")))
}


pub(crate) fn control_agent_config(kv: &str) -> Result<ResultEnvelope> {
    crate::runtime_policy::require_host("agent configuration changes")?;
    anyhow::ensure!(super::lifecycle::current_boot_token().is_none(), "agent config must own maintenance");
    let (key, raw_value) = kv.split_once('=').ok_or_else(|| respire_client_host::input_error::InputError(
        "format must be key=value (e.g. diary_mode=verbose)".into()))?;
    let intent = AgentConfigIntent { key: key.into(), raw_value: raw_value.into() };
    intent.apply(&serde_json::json!({})).map_err(|message|
        respire_client_host::input_error::InputError(message.into()))?;
    control_host_agent_config(intent)
}
