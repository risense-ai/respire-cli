//! Host lifecycle for private account control; business credentials stay in Runtime.

use anyhow::{Context, Result};
use respire_commands::output::{Item, ResultEnvelope, Status};
use respire_protocol::{HostAuthOutcome, HostAuthResult};
use respire_protocol::host_control::{HostAuthAccountOutcome, HostAuthAccountResult, HostAuthAuthorization,
    HostAuthLoginContinuation};
use std::path::Path;

use super::launch_authorization::control;
use super::super::lifecycle;

pub(crate) fn control_register(
    addr: &str, user: &str, password: &str, super_password: Option<&str>,
) -> Result<ResultEnvelope> {
    account_operation(&uuid::Uuid::new_v4().to_string(), None, true,
        control::AccountControl::Register { addr: addr.to_owned(), user: user.to_owned(),
            password: password.to_owned(), super_password: super_password.map(str::to_owned) })
}

pub(crate) fn control_login(
    addr: &str, user: &str, authorization: HostAuthAuthorization, super_password: &str,
) -> Result<ResultEnvelope> {
    control_login_step(addr, user, authorization, Some(super_password), HostAuthLoginContinuation::default(), None)
}

/// Continue only a known AwaitingInput receipt; an uncertain operation is queried, never replayed.
pub(crate) fn control_login_step(
    addr: &str, user: &str, authorization: HostAuthAuthorization, super_password: Option<&str>,
    input: HostAuthLoginContinuation, resume: Option<&HostAuthAccountResult>,
) -> Result<ResultEnvelope> {
    let operation = control::AccountControl::LoginStep {
        addr: addr.to_owned(), user: user.to_owned(), authorization,
        super_password: super_password.map(str::to_owned), input,
    };
    if let Some(previous) = resume {
        control::validate_account_receipt(previous, &previous.operation_id, &previous.source_profile, false)?;
        if previous.outcome != HostAuthAccountOutcome::AwaitingInput {
            return control_account_result(&previous.operation_id, &previous.source_profile, false);
        }
        let status = previous.login.as_ref().context("login continuation status is missing")?;
        anyhow::ensure!(status.user == user && status.addr.trim_end_matches('/') == addr.trim().trim_end_matches('/'),
            "login continuation user or server differs from the original operation");
        return account_operation(&previous.operation_id, Some(&previous.source_profile), false, operation);
    }
    account_operation(&uuid::Uuid::new_v4().to_string(), None, false, operation)
}

/// Original source and operation come from AccountOutcomeUnknown, never a new authentication.
pub(crate) fn control_account_result(
    operation_id: &str, source_profile: &Path, register: bool,
) -> Result<ResultEnvelope> {
    account_operation(operation_id, Some(source_profile), register, control::AccountControl::Result)
}

/// Explicit local compensation only; Runtime decides whether the vault still permits it.
pub(crate) fn control_account_rollback(
    operation_id: &str, source_profile: &Path, register: bool,
) -> Result<ResultEnvelope> {
    account_operation(operation_id, Some(source_profile), register, control::AccountControl::Rollback)
}

fn account_operation(
    operation_id: &str, original_source: Option<&Path>, register: bool, operation: control::AccountControl,
) -> Result<ResultEnvelope> {
    crate::runtime_policy::require_host("private account control")?;
    let id = uuid::Uuid::parse_str(operation_id).context("invalid account operation ID")?;
    anyhow::ensure!(id.get_version_num() == 4 && id.to_string() == operation_id,
        "account operation ID must be a canonical random UUID");
    control::installed_auth_runtime()?;
    let (_, selected) = respire_client_host::config::control_roots()?;
    anyhow::ensure!(lifecycle::current_boot_token().is_none(),
        "private account control must own its maintenance transaction");
    let takeover = crate::runtime_policy::takeover_lock()?;
    if original_source.is_none() {
        std::fs::create_dir_all(&selected)?;
    }
    let source = original_source.unwrap_or(&selected).canonicalize()?;
    let original_identity = control::identity(&source)?;
    let health = crate::rpc::probe_runtime()?;
    anyhow::ensure!(health.is_some() || !crate::rpc::endpoint_path().try_exists()?,
        "account control blocked: recorded owner has no verifiable health/drain receipt");
    let mut maintenance = if original_source.is_some() {
        lifecycle::with_explicit_recovery(lifecycle::begin_maintenance_locked)?
    } else {
        lifecycle::begin_maintenance_locked()?
    };
    // Both service-managed and explicit host-local transactions own a durable marker.
    anyhow::ensure!(maintenance.auth_launch_binding(&selected.canonicalize()?)?.is_some(),
        "account control requires persistent host maintenance; no authentication was sent");
    maintenance.check_account_runtime()?;
    if let Some(health) = health.as_ref() {
        maintenance.drain_runtime(health)?;
    }
    let unknown = || control::AccountOutcomeUnknown {
        operation_id: operation_id.to_owned(), source_profile: source.clone(), register,
    };
    let mut envelope = if let (Some(_), control::AccountControl::LoginStep { addr, user, .. }) = (original_source, &operation) {
        // Query again under takeover: a stale prompt receipt cannot authorize replay after uncertainty.
        let queried = control::auth_account_locked(&takeover, &mut maintenance,
            operation_id, &source, register, control::AccountControl::Result, None)?;
        let receipt: HostAuthAccountResult = serde_json::from_value(queried.summary.clone())
            .map_err(|_| anyhow::anyhow!("invalid login continuation receipt shape").context(unknown()))?;
        if receipt.outcome == HostAuthAccountOutcome::AwaitingInput {
            let status = receipt.login.as_ref().context("login continuation status is missing")?;
            anyhow::ensure!(status.user == *user && status.addr.trim_end_matches('/') == addr.trim().trim_end_matches('/'),
                "queried login user or server differs from the original operation");
            control::auth_account_locked(&takeover, &mut maintenance,
                operation_id, &source, register, operation, None)?
        } else {
            queried
        }
    } else {
        control::auth_account_locked(&takeover, &mut maintenance,
            operation_id, &source, register, operation, None)?
    };
    let mut receipt: HostAuthAccountResult = serde_json::from_value(envelope.summary.clone())
        .map_err(|_| anyhow::anyhow!("invalid account receipt shape"))?;
    if matches!(receipt.outcome, HostAuthAccountOutcome::AwaitingVerification | HostAuthAccountOutcome::Committed) {
        maintenance.start_account_target(&source, operation_id, &receipt, register)
            .map_err(|error| error.context(unknown()))?;
        if matches!(receipt.outcome, HostAuthAccountOutcome::AwaitingVerification) {
            envelope = control::auth_account_locked(&takeover, &mut maintenance, operation_id,
                &source, register, control::AccountControl::Complete, Some(&receipt))?;
            receipt = serde_json::from_value(envelope.summary.clone())
                .map_err(|_| anyhow::anyhow!("invalid account completion receipt shape"))?;
        }
    }
    match receipt.outcome {
        HostAuthAccountOutcome::AwaitingInput => Ok(envelope),
        HostAuthAccountOutcome::Committed => {
            control::verify_account_target(&receipt, operation_id, &source, register)
                .map_err(|error| error.context(unknown()))?;
            maintenance.finish().map_err(|error| error.context(unknown()))?;
            Ok(envelope)
        }
        HostAuthAccountOutcome::RolledBack => {
            // Reconnected callers cannot infer whether the original source was serving.
            if original_source.is_none() {
                anyhow::ensure!(control::identity(&source)? == original_identity,
                    "account rollback did not restore the original source identity; maintenance retained");
                if health.is_some() {
                    maintenance.start_account_runtime()?;
                }
                maintenance.finish()?;
            }
            Ok(envelope)
        }
        HostAuthAccountOutcome::AwaitingVerification | HostAuthAccountOutcome::Unknown => Err(unknown().into()),
    }
}

/// New keygen operation. The legacy pass argument is deliberately not a credential.
pub(crate) fn control_keygen(pass: Option<&str>, force: bool) -> Result<ResultEnvelope> {
    if pass.is_some() {
        eprintln!("INFO from v4, --pass is not used for encryption: the super password is system-generated; copy the output below");
    }
    keygen_operation(&uuid::Uuid::new_v4().to_string(), force, false)
}

/// Query the original write, never issue another keygen or choose a new operation ID.
pub(crate) fn control_auth_result(operation_id: &str, force: bool) -> Result<ResultEnvelope> {
    keygen_operation(operation_id, force, true)
}

fn keygen_operation(operation_id: &str, force: bool, query_only: bool) -> Result<ResultEnvelope> {
    crate::runtime_policy::require_host("private account control")?;
    let id = uuid::Uuid::parse_str(operation_id).context("invalid auth operation ID")?;
    anyhow::ensure!(id.get_version_num() == 4 && id.to_string() == operation_id,
        "auth operation ID must be a canonical random UUID");
    control::installed_auth_runtime()?;
    // Validate configuration before takeover acquisition can create its lock directory.
    let (_, profile) = respire_client_host::config::control_roots()?;
    anyhow::ensure!(lifecycle::current_boot_token().is_none(),
        "private account control must own its maintenance transaction");
    let takeover = crate::runtime_policy::takeover_lock()?;
    if !query_only {
        std::fs::create_dir_all(&profile)?;
    }
    let health = crate::rpc::probe_runtime()?;
    anyhow::ensure!(health.is_some() || !crate::rpc::endpoint_path().try_exists()?,
        "account control blocked: recorded owner has no verifiable health/drain receipt");
    let mut maintenance = if query_only {
        lifecycle::with_explicit_recovery(lifecycle::begin_maintenance_locked)?
    } else {
        lifecycle::begin_maintenance_locked()?
    };
    if let Some(health) = health.as_ref() {
        maintenance.drain_runtime(health)?;
    }
    let response = if query_only {
        control::auth_result_locked(&takeover, &mut maintenance, operation_id, force)
    } else {
        control::auth_keygen_locked(&takeover, &mut maintenance, operation_id, force)
    };
    finish_keygen(response, operation_id, force, query_only, || {
        if health.is_some() {
            maintenance.start_account_runtime()?;
        }
        maintenance.finish()
    })
}

pub(super) fn finish_keygen(
    response: Result<ResultEnvelope>,
    operation_id: &str,
    force: bool,
    query_only: bool,
    finish_rollback: impl FnOnce() -> Result<()>,
) -> Result<ResultEnvelope> {
    // An exchange error leaves the durable Paused marker intact, including cleanup failures.
    let envelope = response?;
    let result: HostAuthResult = serde_json::from_value(envelope.summary.clone())
        .map_err(|_| anyhow::anyhow!("invalid auth control result shape"))?;
    match result.outcome {
        HostAuthOutcome::Committed => {
            let secret = result.super_password.filter(|value| !value.is_empty())
                .context("committed auth result is missing the recovery code")?;
            // Unbound keys cannot serve business requests. Register/login must resume Paused.
            let mut output = ResultEnvelope::new("keygen", Status::Ok,
                serde_json::json!({"path": result.path.to_string_lossy(), "super": secret}),
                vec![Item::new("keys", Status::Ok, result.path.display().to_string())]);
            output.actions.push("login --interactive --user <user> --pass <password>".into());
            Ok(output)
        }
        HostAuthOutcome::RolledBack => {
            // A new query process does not know the original serving state. Leave it Paused.
            if !query_only {
                finish_rollback()?;
            }
            Ok(envelope)
        }
        HostAuthOutcome::Unknown => Err(control::AuthOutcomeUnknown {
            operation_id: operation_id.to_owned(), force,
        }.into()),
    }
}
