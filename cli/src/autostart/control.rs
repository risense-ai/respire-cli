//! Auth-only client. Lifecycle ownership stays with the host caller; keys stay in Runtime.
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use respire_client_host::identity::{auth_session_identity, AuthSessionIdentity};
use respire_client_host::lock::LibraryLock;
use respire_commands::output::{ResultEnvelope, Status};
use respire_protocol::{
    ControlBinding, HostAuthIdentity, HostAuthKeygenParams, HostAuthOutcome, HostAuthResult,
    HostControlLaunchGrant, RpcRequest, RpcResponse,
    HOST_AUTH_KEYGEN_METHOD, HOST_AUTH_RESULT_METHOD, HOST_AUTH_SCHEMA_V,
};

/// A failed exchange cannot prove that the write did not commit. Never replay it.
#[derive(Debug)]
pub(crate) struct AuthOutcomeUnknown {
    pub operation_id: String,
    pub force: bool,
}

impl std::fmt::Display for AuthOutcomeUnknown {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(out, "auth_outcome_unknown operation_id={} force={}; query the same operation, do not replay keygen",
            self.operation_id, self.force)
    }
}
impl std::error::Error for AuthOutcomeUnknown {}

/// Caller holds takeover and has drained the serving owner under maintenance.
/// It must not hold installation/profile LibraryLock while waiting for the helper.
pub(crate) fn auth_keygen_locked(
    takeover: &LibraryLock,
    maintenance: &mut super::lifecycle::Maintenance,
    operation_id: &str,
    force: bool,
) -> Result<ResultEnvelope> {
    auth_request(takeover, maintenance, operation_id, force, false)
}

/// Reconnect with the original operation ID and force; this never issues keygen.
pub(crate) fn auth_result_locked(
    takeover: &LibraryLock,
    maintenance: &mut super::lifecycle::Maintenance,
    operation_id: &str,
    force: bool,
) -> Result<ResultEnvelope> {
    auth_request(takeover, maintenance, operation_id, force, true)
}

fn identity(profile: &Path) -> Result<HostAuthIdentity> {
    Ok(match auth_session_identity(profile, super::hash)? {
        AuthSessionIdentity::Absent => HostAuthIdentity::Absent,
        AuthSessionIdentity::Unbound { operation_id, session_sha256 } =>
            HostAuthIdentity::Unbound { operation_id, session_sha256 },
        AuthSessionIdentity::Bound { account_id, session_sha256 } =>
            HostAuthIdentity::Bound { account_id, session_sha256 },
    })
}

fn auth_request(
    takeover: &LibraryLock,
    maintenance: &mut super::lifecycle::Maintenance,
    operation_id: &str,
    force: bool,
    query_only: bool,
) -> Result<ResultEnvelope> {
    crate::runtime_policy::require_host("private account control")?;
    let id = uuid::Uuid::parse_str(operation_id).context("invalid auth operation ID")?;
    anyhow::ensure!(id.get_version_num() == 4 && id.to_string() == operation_id,
        "auth operation ID must be a canonical random UUID");
    let deadline = Instant::now() + Duration::from_secs(12);
    let binary = crate::runtime_fetch::managed_runtime_path()?
        .context("auth control requires an installed managed Runtime")?.canonicalize()?;
    let manifest = crate::runtime_fetch::read_manifest()?
        .context("auth control Runtime manifest is missing")?;
    anyhow::ensure!(crate::runtime_fetch::version_in_accept(&manifest.version)
        && super::hash_file(&binary)?.eq_ignore_ascii_case(&manifest.sha256),
        "auth control Runtime version or image does not match the managed manifest");
    let (root, profile) = respire_client_host::config::control_roots()?;
    let root = root.canonicalize()?;
    let profile = profile.canonicalize()?;
    anyhow::ensure!(takeover.protects(&root.join("runtime/takeover"))?,
        "auth control requires this installation's takeover ownership");
    let maintenance = maintenance.auth_launch_binding(&profile)?;
    let expected = identity(&profile)?;
    let account_id = match &expected {
        HostAuthIdentity::Bound { account_id, .. } => Some(account_id.clone()),
        _ => None,
    };
    let grant_account = account_id.clone()
        .unwrap_or_else(|| super::hash(profile.display().to_string().as_bytes()));
    let registration = super::read_registration(&root)?;
    let managed_id = registration.as_ref()
        .filter(|config| config.enabled && !config.manually_stopped)
        .map(|config| config.id.as_str());
    let (grant, _) = super::prepare_grant_for_identity(&binary, &root, &profile,
        managed_id, crate::net_rpc::rpc_port(), &grant_account,
        maintenance)?;
    let grant: HostControlLaunchGrant = serde_json::from_value(grant)?;
    anyhow::ensure!(grant.image_path == binary
        && grant.image_sha256.eq_ignore_ascii_case(&manifest.sha256)
        && identity(&profile)? == expected,
        "auth control image or identity changed while preparing authorization");
    let params = HostAuthKeygenParams {
        schema_version: HOST_AUTH_SCHEMA_V,
        binding: ControlBinding { installation_root: root, profile: profile.clone(),
            launch_id: grant.instance_id.clone(), expected_account_id: account_id },
        identity: expected,
        force,
    };
    let request = RpcRequest {
        v: respire_commands::rpc_client::PROTOCOL_V,
        id: uuid::Uuid::new_v4().to_string(),
        method: if query_only { HOST_AUTH_RESULT_METHOD } else { HOST_AUTH_KEYGEN_METHOD }.to_owned(),
        args: vec![serde_json::to_string(&params)?],
        scope: None, operation_id: Some(operation_id.to_owned()),
        idempotency_key: Some(operation_id.to_owned()), parent_operation_id: None,
        queue_wait_ms: None, lifecycle: None,
    };
    // Exactly one exchange: errors retain the original operation, never retry a write.
    super::exchange_control(&binary, &grant, &request, deadline, |response, pid| {
        validate_auth_response(response, &request, &profile, pid)
    }).map_err(|error| error.context(AuthOutcomeUnknown { operation_id: operation_id.to_owned(), force }))
}

pub(super) fn validate_auth_response(
    response: RpcResponse<ResultEnvelope>,
    request: &RpcRequest,
    profile: &Path,
    pid: u32,
) -> Result<ResultEnvelope> {
    anyhow::ensure!(response.v == request.v && response.id == request.id
        && response.bin == "rsrs-runtime" && response.pid == Some(pid)
        && response.operation_id == request.operation_id
        && response.idempotency_key == request.idempotency_key
        && response.scope.is_none() && response.web_url.is_none(),
        "auth control response identity mismatch");
    if let Some(directory) = &response.data_dir {
        anyhow::ensure!(Path::new(directory).canonicalize()? == profile,
            "auth control response profile mismatch");
    }
    let envelope = response.envelope.context("auth control result is missing")?;
    anyhow::ensure!(envelope.command == "keygen", "unexpected auth control command");
    anyhow::ensure!(!matches!(response.code.as_deref(),
        Some("control_outcome_unknown" | "auth_outcome_unknown")),
        "auth control completion is unknown; query the original operation");
    for (name, value) in [("control_ready", "true"), ("store_ready", "false")] {
        let mut items = envelope.items.iter().filter(|item| item.name == name);
        anyhow::ensure!(items.next().is_some_and(|item| item.value == value
            && if name == "control_ready" { matches!(item.status, Status::Ok) }
                else { matches!(item.status, Status::Skip) }) && items.next().is_none(),
            "auth control readiness was not confirmed");
    }
    // Do not echo untrusted response/error contents into diagnostics.
    let result: HostAuthResult = serde_json::from_value(envelope.summary.clone())
        .map_err(|_| anyhow::anyhow!("invalid auth control result shape"))?;
    anyhow::ensure!(Some(result.operation_id.as_str()) == request.operation_id.as_deref()
        && result.path == profile.join("session.json"), "auth control result owner mismatch");
    match result.outcome {
        HostAuthOutcome::Committed => {
            anyhow::ensure!(response.ok && response.exit == 0 && response.code.is_none()
                && response.error.is_none() && matches!(envelope.status, Status::Ok)
                && envelope.errors.is_empty()
                && result.super_password.as_deref().is_some_and(|value| !value.is_empty()),
                "invalid committed auth result");
            let actual = identity(profile)?;
            anyhow::ensure!(matches!(&actual, HostAuthIdentity::Unbound { operation_id, session_sha256 }
                if operation_id == &result.operation_id && Some(session_sha256) == result.session_sha256.as_ref()),
                "committed auth session does not match the Runtime receipt");
        }
        HostAuthOutcome::RolledBack => {
            anyhow::ensure!(!response.ok && response.exit == 2
                && response.code.as_deref() == Some("auth_not_committed")
                && response.error.is_none() && matches!(envelope.status, Status::Fail)
                && envelope.errors.is_empty() && result.session_sha256.is_none()
                && result.super_password.is_none(), "invalid rolled-back auth result");
        }
        HostAuthOutcome::Unknown => anyhow::bail!("auth control completion is unknown; query the original operation"),
    }
    Ok(envelope)
}
