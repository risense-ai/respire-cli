//! Host-owned secret reads and fixed private cloud identity reads.
//! Caller owns maintenance/drain/resume; display and export files remain on this host.

use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use respire_client_host::lock::LibraryLock;
use respire_commands::output::{ResultEnvelope, Status as OutputStatus, Item as OutputItem};
use respire_protocol::{RpcRequest, RpcResponse};
use respire_protocol::identity_control::{
    HostIdentitySessionListParams, HostIdentitySessionListResult,
    HOST_IDENTITY_SCHEMA_V, HOST_IDENTITY_SESSION_LIST_METHOD,
};
use respire_protocol::secret_control::{
    HostKeysExportReadResult, HostSecretReadResult,
};

/// Complete host transaction; no secret leaves this module before owner restoration.
pub(crate) fn control_secret(reveal: bool) -> Result<ResultEnvelope> {
    match control_read(ReadKind::Secret(reveal))? {
        ReadResult::Secret(read) => secret_result(read, reveal),
        _ => anyhow::bail!("private secret read returned the wrong result kind"),
    }
}

pub(crate) fn control_keys_export(out: Option<&str>) -> Result<ResultEnvelope> {
    match control_read(ReadKind::KeysExport)? {
        ReadResult::KeysExport(read) => keys_export_result(read, out),
        _ => anyhow::bail!("private key export returned the wrong result kind"),
    }
}

/// Return cloud details only after the original owner has been restored and verified.
pub(crate) fn control_session_list() -> Result<serde_json::Value> {
    match control_read(ReadKind::SessionList)? {
        ReadResult::SessionList(read) => Ok(read.details),
        _ => anyhow::bail!("private session list returned the wrong result kind"),
    }
}

enum ReadResult {
    Secret(HostSecretReadResult),
    KeysExport(HostKeysExportReadResult),
    SessionList(HostIdentitySessionListResult),
}

fn control_read(kind: ReadKind) -> Result<ReadResult> {
    crate::runtime_policy::require_host("private secret read")?;
    anyhow::ensure!(super::lifecycle::current_boot_token().is_none(),
        "private secret read must own its host maintenance transaction");
    let takeover = crate::runtime_policy::takeover_lock()?;
    // Match the existing model bootstrap: install only an absent official component.
    if crate::runtime_fetch::read_manifest()?.is_none() {
        crate::runtime_fetch::download_and_install(None, None)?;
    }
    let (binary, manifest) = super::model_control::installed_model_runtime()?;
    let (root, profile) = respire_client_host::config::control_roots()?;
    std::fs::create_dir_all(&root)?;
    std::fs::create_dir_all(&profile)?;
    let root = root.canonicalize()?;
    let profile = profile.canonicalize()?;
    let expected = super::control::identity(&profile)?;
    let account_id = match &expected {
        respire_protocol::HostAuthIdentity::Bound { account_id, .. } => account_id.clone(),
        _ => super::hash(profile.display().to_string().as_bytes()),
    };
    let registration = super::read_registration(&root)?;
    let managed = registration.as_ref().filter(|config| config.enabled && !config.manually_stopped);
    let owner = crate::rpc::probe_runtime()?;
    anyhow::ensure!(owner.is_some() || !crate::rpc::endpoint_path().try_exists()?,
        "private secret read has a recorded owner without verifiable health");
    if let Some(config) = managed {
        super::lifecycle::owned(config)?;
        super::lifecycle::ensure_control_endpoint(config)?;
        let state = super::super::super::manager::inspect(config)?;
        anyhow::ensure!(owner.is_some() || !state.running,
            "private secret read cannot identify the registered supervisor's running owner");
    }
    if let Some(owner) = owner.as_ref() {
        super::model_control::verify_model_owner(owner, &root, &profile, managed, &binary, &manifest, Some(&account_id))?;
    }
    let unchanged = || -> Result<()> {
        let (current_binary, current_manifest) = super::model_control::installed_model_runtime()?;
        let (current_root, current_profile) = respire_client_host::config::control_roots()?;
        anyhow::ensure!(current_binary == binary && current_manifest.version == manifest.version
            && current_manifest.sha256.eq_ignore_ascii_case(&manifest.sha256)
            && current_root.canonicalize()? == root && current_profile.canonicalize()? == profile
            && super::control::identity(&profile)? == expected,
            "private secret read installation, profile or identity changed");
        Ok(())
    };
    let mut maintenance = super::lifecycle::begin_maintenance_locked()?;
    let result: Result<ReadResult> = (|| {
        maintenance.auth_launch_binding(&profile)?
            .context("private secret read requires persistent Paused host maintenance")?;
        maintenance.check_account_runtime()?;
        if let Some(owner) = owner.as_ref() { maintenance.drain_runtime(owner)?; }
        anyhow::ensure!(!crate::net_rpc::port_is_open(),
            "private secret read requires the serving Runtime to be drained");
        unchanged()?;
        let read = match kind {
            ReadKind::Secret(reveal) => ReadResult::Secret(secret_read_locked(&takeover, &mut maintenance, reveal)?),
            ReadKind::KeysExport => ReadResult::KeysExport(keys_export_read_locked(&takeover, &mut maintenance)?),
            ReadKind::SessionList => ReadResult::SessionList(session_list_read_locked(&takeover, &mut maintenance)?),
        };
        unchanged()?;
        if let Some(original) = owner.as_ref() {
            maintenance.start_account_runtime()?;
            let restored = crate::rpc::probe_runtime()?.context("original secret read owner did not resume")?;
            super::model_control::verify_model_owner(&restored, &root, &profile, managed, &binary, &manifest, Some(&account_id))?;
            anyhow::ensure!(!original.store_ready || restored.store_ready,
                "restored secret read owner did not confirm its original store readiness");
        }
        unchanged()?;
        maintenance.finish()?;
        Ok(read)
    })();
    match result {
        Ok(read) => { maintenance.finish_handoff()?; Ok(read) },
        Err(error) => {
            if let Err(pause) = maintenance.mark(super::lifecycle::Phase::Paused) {
                return Err(error.context(format!("private secret read failed; Paused marker publication failed: {pause:#}")));
            }
            Err(error.context("private secret read failed; maintenance remains Paused"))
        }
    }
}

pub(crate) fn secret_read_locked(
    takeover: &LibraryLock,
    maintenance: &mut super::lifecycle::Maintenance,
    reveal: bool,
) -> Result<HostSecretReadResult> {
    read_host_locked(takeover, maintenance, |session| {
        let factors = if reveal {
            session.map(respire_client_host::host_credentials::read_export_factors).transpose()?
        } else { None };
        let (super_password, legacy_secret) = factors.unwrap_or((None, None));
        respire_host_control::keys_export::secret_read(session, reveal,
            super_password.as_deref(), legacy_secret.as_deref())
    })
}

pub(crate) fn keys_export_read_locked(
    takeover: &LibraryLock,
    maintenance: &mut super::lifecycle::Maintenance,
) -> Result<HostKeysExportReadResult> {
    read_host_locked(takeover, maintenance, |session| {
        respire_client_host::settings::ensure_writable()?;
        let session = session.context("key export session is unavailable")?;
        let (super_password, legacy_secret) = respire_client_host::host_credentials::read_export_factors(session)?;
        respire_host_control::keys_export::keys_export(session, super_password.as_deref(), legacy_secret.as_deref())
    })
}

/// Hold the same root/profile ownership as the old helper, then recheck before exposing secrets.
fn read_host_locked<T>(
    takeover: &LibraryLock,
    maintenance: &mut super::lifecycle::Maintenance,
    read: impl FnOnce(Option<&serde_json::Value>) -> Result<T>,
) -> Result<T> {
    crate::runtime_policy::require_host("host secret read")?;
    let (root, profile) = respire_client_host::config::control_roots()?;
    let root = root.canonicalize()?;
    let profile = profile.canonicalize()?;
    anyhow::ensure!(takeover.protects(&root.join("runtime/takeover"))?,
        "secret read requires this installation's takeover ownership");
    maintenance.auth_launch_binding(&profile)?.context("secret read requires Paused maintenance")?;
    anyhow::ensure!(!crate::net_rpc::port_is_open(), "secret read requires the Runtime to be drained");
    let wait = Duration::from_secs(1);
    let _root_lock = LibraryLock::acquire(&root, wait)?;
    let _profile_lock = if profile == root { None } else { Some(LibraryLock::acquire(&profile, wait)?) };
    let journal_path = respire_client_host::config::normalize_control_path(&root.join(".login-recovery.json"))?;
    match std::fs::read(journal_path) {
        Ok(bytes) => {
            let journal: serde_json::Value = serde_json::from_slice(&bytes)
                .context("invalid authentication recovery record; retain it for recovery")?;
            anyhow::ensure!(journal["schema_version"] == 2 && journal.get("active").is_some_and(serde_json::Value::is_null),
                "auth_recovery_pending: finish account recovery before reading secrets");
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("authentication recovery record is unavailable"),
    }
    let expected = super::control::identity(&profile)?;
    let session_path = respire_client_host::config::normalize_control_path(&profile.join("session.json"))?;
    let snapshot = || -> Result<Option<Vec<u8>>> {
        match std::fs::read(&session_path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error).context("secret read session is unavailable"),
        }
    };
    let bytes = snapshot()?;
    let session = bytes.as_deref().map(serde_json::from_slice::<serde_json::Value>).transpose()
        .map_err(|_| anyhow::anyhow!("invalid secret read session"))?;
    let result = read(session.as_ref())?;
    let (current_root, current_profile) = respire_client_host::config::control_roots()?;
    anyhow::ensure!(current_root.canonicalize()? == root && current_profile.canonicalize()? == profile
        && super::control::identity(&profile)? == expected && snapshot()? == bytes,
        "secret read installation, selection or session changed");
    maintenance.auth_launch_binding(&profile)?.context("secret read lost its Paused maintenance ownership")?;
    Ok(result)
}

fn session_list_read_locked(
    takeover: &LibraryLock,
    maintenance: &mut super::lifecycle::Maintenance,
) -> Result<HostIdentitySessionListResult> {
    let envelope = read_locked(takeover, maintenance)?;
    serde_json::from_value(envelope.details)
        .map_err(|_| anyhow::anyhow!("invalid private session list result"))
}

enum ReadKind { Secret(bool), KeysExport, SessionList }

fn read_locked(
    takeover: &LibraryLock,
    maintenance: &mut super::lifecycle::Maintenance,
) -> Result<ResultEnvelope> {
    crate::runtime_policy::require_host("private secret read")?;
    let (root, profile) = respire_client_host::config::control_roots()?;
    let root = root.canonicalize()?;
    let profile = profile.canonicalize()?;
    let expected = super::control::identity(&profile)?;
    maintenance.auth_launch_binding(&profile)?
        .context("private secret read requires an actual Paused maintenance grant")?;
    let method = HOST_IDENTITY_SESSION_LIST_METHOD;
    let command = "session";
    let timeout = Duration::from_secs(35);
    // Reuse installed-image verification, grant creation, identity and the bounded exchange.
    let envelope = super::control::auth_exchange(takeover, maintenance,
        Instant::now() + timeout, None,
        |binding, identity| {
            anyhow::ensure!(binding.installation_root == root && binding.profile == profile && identity == expected,
                "private secret read scope changed while authorizing");
            let argument = serde_json::to_string(&HostIdentitySessionListParams {
                schema_version: HOST_IDENTITY_SCHEMA_V, binding, identity,
            }).map_err(|_| anyhow::anyhow!("cannot encode private session list request"))?;
            Ok(RpcRequest { v: respire_commands::rpc_client::PROTOCOL_V,
                id: uuid::Uuid::new_v4().to_string(), method: method.to_owned(), args: vec![argument],
                scope: None, operation_id: None, idempotency_key: None, parent_operation_id: None,
                queue_wait_ms: None, lifecycle: None })
        },
        |response, request, selected, pid| validate_response(response, request, selected, pid, command),
        |error| error.context("private secret read failed"))?;
    let (current_root, current_profile) = respire_client_host::config::control_roots()?;
    anyhow::ensure!(current_root.canonicalize()? == root && current_profile.canonicalize()? == profile
        && super::control::identity(&profile)? == expected,
        "private secret read scope changed during the exchange");
    maintenance.auth_launch_binding(&profile)?
        .context("private secret read lost its Paused maintenance grant")?;
    Ok(envelope)
}

fn validate_response(
    response: RpcResponse<ResultEnvelope>, request: &RpcRequest, profile: &Path, pid: u32, command: &str,
) -> Result<ResultEnvelope> {
    anyhow::ensure!(response.v == request.v && response.id == request.id
        && response.bin == "rsrs-runtime" && response.pid == Some(pid)
        && response.scope.is_none() && response.operation_id.is_none() && response.idempotency_key.is_none()
        && response.web_url.is_none(), "private secret read response identity mismatch");
    if response.code.as_deref() == Some("auth_recovery_pending") {
        anyhow::bail!("auth_recovery_pending: finish account recovery before reading secrets");
    }
    if let Some(directory) = &response.data_dir {
        anyhow::ensure!(Path::new(directory).canonicalize()? == profile, "private secret read response profile mismatch");
    }
    // Do not propagate peer error strings or decode errors that could contain secret data.
    anyhow::ensure!(response.ok && response.exit == 0 && response.code.is_none() && response.error.is_none(),
        "private Runtime secret read was rejected");
    let envelope = response.envelope.context("private secret read response envelope is missing")?;
    let expected_summary = if command == "session" {
        serde_json::json!({"action":"list"})
    } else { serde_json::json!({}) };
    anyhow::ensure!(envelope.command == command && matches!(envelope.status, OutputStatus::Ok)
        && envelope.summary == expected_summary && envelope.errors.is_empty()
        && envelope.actions.is_empty() && envelope.items.len() == 2,
        "invalid private secret read response envelope");
    for (name, value) in [("control_ready", "true"), ("store_ready", "false")] {
        let mut items = envelope.items.iter().filter(|item| item.name == name);
        anyhow::ensure!(items.next().is_some_and(|item| item.value == value
            && if name == "control_ready" { matches!(item.status, OutputStatus::Ok) }
               else { matches!(item.status, OutputStatus::Skip) }) && items.next().is_none(),
            "private secret read readiness was not confirmed");
    }
    Ok(envelope)
}

fn validate_secret_result(read: &HostSecretReadResult, reveal: bool) -> Result<()> {
    anyhow::ensure!(if read.session.has_session && reveal {
        read.secret.is_some() && read.five.as_ref().is_some_and(serde_json::Value::is_object)
    } else { read.secret.is_none() && read.five.is_none() }, "invalid secret reveal result");
    Ok(())
}

/// Render only after the private exchange and post-read scope checks have succeeded.
pub(crate) fn secret_result(read: HostSecretReadResult, reveal: bool) -> Result<ResultEnvelope> {
    validate_secret_result(&read, reveal)?;
    let info = read.session;
    if !info.has_session {
        let mut result = ResultEnvelope::new(
            "secret",
            OutputStatus::Skip,
            serde_json::json!({"session":false}),
            vec![OutputItem::new(
                "session",
                OutputStatus::Skip,
                "not available",
            )],
        );
        result.actions.push("register or login".into());
        return Ok(result);
    }
    let mut items = vec![
        OutputItem::new("user", OutputStatus::Ok, info.user.clone()),
        OutputItem::new("address", OutputStatus::Ok, info.addr.clone()),
        OutputItem::new(
            "token",
            OutputStatus::Ok,
            if info.has_token { "present" } else { "missing" },
        ),
    ];
    let mut details = serde_json::json!({"session":serde_json::to_value(&info)?});
    if reveal {
        let secret = read.secret.context("private secret reveal is missing")?;
        let five = read.five.context("private key reveal is missing")?;
        items.push(OutputItem::new(
            "secret",
            OutputStatus::Warn,
            secret.clone(),
        ));
        items.push(OutputItem::new(
            "keys",
            OutputStatus::Warn,
            serde_json::to_string(&five)?,
        ));
        details["secret"] = serde_json::json!(secret);
        details["five"] = five;
    } else {
        items.push(OutputItem::new(
            "secret",
            OutputStatus::Ok,
            info.secret_masked,
        ));
    }
    let mut result = ResultEnvelope::new(
        "secret",
        if reveal {
            OutputStatus::Warn
        } else {
            OutputStatus::Ok
        },
        serde_json::json!({"reveal":reveal,"user":info.user}),
        items,
    );
    result.details = details;
    if reveal {
        result.actions.push("protect secret output".into());
    }
    Ok(result)
}

/// Keep the original inline output and --out file behavior in the local CLI.
pub(crate) fn keys_export_result(read: HostKeysExportReadResult, out: Option<&str>) -> Result<ResultEnvelope> {
    let HostKeysExportReadResult { version, user, body, legacy_warning } = read;
    if legacy_warning {
        eprintln!("WARN this profile retains its original v1/v2 factors; migrate the complete library explicitly before cloud namespace publication");
    }
    match out {
        Some(path) => {
            #[cfg(unix)]
            {
                use std::io::Write;
                use std::os::unix::fs::OpenOptionsExt;
                let mut f = std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(path)?;
                f.write_all(body.as_bytes())?;
            }
            #[cfg(not(unix))]
            std::fs::write(path, &body)?;
            let mut result = ResultEnvelope::new(
                "keys-export",
                OutputStatus::Ok,
                serde_json::json!({"path":path,"version":version,"user":user}),
                vec![OutputItem::new("file", OutputStatus::Ok, path)],
            );
            result
                .actions
                .push("protect file; it contains decrypt secrets".into());
            Ok(result)
        }
        None => {
            let mut result = ResultEnvelope::new(
                "keys-export",
                OutputStatus::Warn,
                serde_json::json!({"version":version,"user":user,"inline":true}),
                vec![OutputItem::new("content", OutputStatus::Warn, body)],
            );
            result
                .actions
                .push("use --out <file> for protected storage".into());
            Ok(result)
        }
    }
}

#[cfg(test)]
#[path = "control_tests/secret_control.rs"]
mod tests;
